package mail

import (
	"bufio"
	"errors"
	"net"
	"strings"

	"github.com/emersion/go-imap"
	imapClient "github.com/emersion/go-imap/client"
	"github.com/go-mail/mail/v2"
	"github.com/matcornic/hermes/v2"
	"github.com/spf13/cast"
)

type Config struct {
	Inbound struct {
		Host string `json:"host"`
		Pass string `json:"pass"`
		User string `json:"user"`
	} `json:"inbound"`
	Outbound struct {
		Host string `json:"host"`
		Pass string `json:"pass"`
		User string `json:"user"`
	} `json:"outbound"`
}

type FoundMail struct {
	Address string
	DKIM    string
}

var MailInfo = hermes.Hermes{
	Product: hermes.Product{
		Copyright: "Global Cyber Alliance",
		Name:      "Domain Security Scanner",
		Link:      "",
		Logo:      "https://www.globalcyberalliance.org/wp-content/uploads/Global-Cyber-Alliance-GCA-Logo-Full-Color.png",
	},
}

// GetMail returns the most recent mail found within the logged-in user's mailbox
func (s *Server) GetMail() (map[string]FoundMail, error) {
	client, err := s.Login()
	if err != nil {
		return nil, err
	}

	defer client.Logout()

	mailbox, err := client.Select("INBOX", false)
	if err != nil {
		return nil, err
	}

	// check for new emails
	from := uint32(1)
	to := mailbox.Messages
	if mailbox.Messages == 0 {
		return nil, errors.New("no new messages")
	}

	seqset := new(imap.SeqSet)
	seqset.AddRange(from, to)

	messages := make(chan *imap.Message, 10)
	done := make(chan error, 1)
	go func() {
		done <- client.Fetch(seqset, []imap.FetchItem{imap.FetchEnvelope, "BODY[HEADER]"}, messages)
	}()

	addresses := make(map[string]FoundMail)
	var emailsToBeDeleted []uint32
	for msg := range messages {
		// DKIM
		headerSection, _ := imap.ParseBodySectionName("RFC822.HEADER")
		header := msg.GetBody(headerSection)
		bscanner := bufio.NewScanner(header)
		var dkimDone, dkimFound bool
		var dkim string
		for bscanner.Scan() {
			if dkimFound {
				if bscanner.Text() != strings.TrimSpace(bscanner.Text()) {
					dkim = dkim + bscanner.Text()
				} else {
					dkimDone = true
					dkimFound = false
				}
			}
			if !dkimDone {
				if strings.Contains(bscanner.Text(), "DKIM-Signature") {
					dkimFound = true
					dkim = dkim + strings.Trim(bscanner.Text(), "DKIM-Signature:")
				}
			}
		}

		if dkimDone {
			dkim = strings.ReplaceAll(dkim, " ", "")
			dkim = strings.ReplaceAll(dkim, ";", "; ")
		}

		// GENERAL
		addresses[msg.Envelope.From[0].HostName] = FoundMail{
			Address: msg.Envelope.From[0].Address(),
			DKIM:    dkim,
		}
		emailsToBeDeleted = append(emailsToBeDeleted, msg.SeqNum)
	}

	if err = <-done; err != nil {
		return nil, err
	}

	// Mark messages as deleted
	flags := []interface{}{imap.DeletedFlag}
	item := imap.FormatFlagsOp(imap.AddFlags, true)
	seqSet := new(imap.SeqSet)
	seqSet.AddNum(emailsToBeDeleted...)

	if err = client.Store(seqSet, item, flags, nil); err != nil {
		return nil, err
	}

	// Permanently delete all marked emails
	if err = client.Expunge(nil); err != nil {
		return nil, err
	}

	if len(addresses) == 0 {
		return nil, errors.New("no valid messages")
	}

	return addresses, nil
}

// Login initializes an open session to the configured IMAP server
func (s *Server) Login() (*imapClient.Client, error) {
	client, err := imapClient.DialTLS(s.config.Inbound.Host, nil)
	if err != nil {
		return nil, err
	}

	if err = client.Login(s.config.Inbound.User, s.config.Inbound.Pass); err != nil {
		return nil, err
	}

	return client, nil
}

// SendMail takes a hermes.Email object, converts it into both html and plaintext,
// and then send the email to the provided mailbox
func (s *Server) SendMail(mailbox string, email hermes.Email) error {
	// Generate an HTML email with the provided contents (for modern clients)
	html, err := MailInfo.GenerateHTML(email)
	if err != nil {
		return err
	}

	// Generate the plaintext version of the e-mail (for clients that do not support xHTML)
	plaintext, err := MailInfo.GeneratePlainText(email)
	if err != nil {
		return err
	}

	m := mail.NewMessage()
	m.SetHeaders(map[string][]string{
		"From":    {s.config.Outbound.User},
		"To":      {mailbox},
		"Subject": {"Email Security Scan Results"},
	})
	m.SetBody("text/plain", plaintext)
	m.AddAlternative("text/html", html)

	host, port, err := net.SplitHostPort(s.config.Outbound.Host)
	if err != nil {
		return err
	}

	d := mail.NewDialer(host, cast.ToInt(port), s.config.Outbound.User, s.config.Outbound.Pass)
	d.StartTLSPolicy = mail.MandatoryStartTLS

	if err = d.DialAndSend(m); err != nil {
		return err
	}

	return nil
}

func stringify(array []string) (result string) {
	if len(array) > 0 {
		for _, s := range array {
			if len(result) == 0 {
				result = s
			} else {
				result = result + "\n" + s
			}
		}
	}

	return result
}
