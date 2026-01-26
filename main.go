package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

type WebhookPayload struct {
	Events []Event `json:"events"`
}

type Event struct {
	ID        string          `json:"id"`
	Live      bool            `json:"live"`
	Processed bool            `json:"processed"`
	Type      string          `json:"type"`
	Created   int64           `json:"created"`
	Data      json.RawMessage `json:"data"`
}

type OrderData struct {
	ID           string   `json:"id"`
	Reference    string   `json:"reference"`
	Currency     string   `json:"currency"`
	Total        any      `json:"total"`
	TotalDisplay string   `json:"totalDisplay"`
	Customer     Customer `json:"customer"`
	Items        []Item   `json:"items"`
}

type Customer struct {
	First   string `json:"first"`
	Last    string `json:"last"`
	Email   string `json:"email"`
	Company string `json:"company"`
}

type Item struct {
	Product         string `json:"product"`
	Display         string `json:"display"`
	Quantity        any    `json:"quantity"`
	Price           any    `json:"price"`
	Subtotal        any    `json:"subtotal"`
	SubtotalDisplay string `json:"subtotalDisplay"`
}

type SubscriptionData struct {
	ID           string   `json:"id"`
	Subscription string   `json:"subscription"`
	Product      string   `json:"product"`
	Currency     string   `json:"currency"`
	Total        any      `json:"total"`
	TotalDisplay string   `json:"totalDisplay"`
	Customer     Customer `json:"customer"`
	State        string   `json:"state"`
	NextDate     string   `json:"next"`
	EndDate      string   `json:"end"`
}

type ReturnData struct {
	ID           string   `json:"id"`
	OrderID      string   `json:"order"`
	Currency     string   `json:"currency"`
	Total        any      `json:"total"`
	TotalDisplay string   `json:"totalDisplay"`
	Customer     Customer `json:"customer"`
	Reason       string   `json:"reason"`
}

type QuoteData struct {
	Quote          string   `json:"quote"`
	QuoteName      string   `json:"quoteName"`
	QuoteStatus    string   `json:"quoteStatus"`
	QuoteCurrency  string   `json:"quoteCurrency"`
	Total          string   `json:"total"`
	TotalDisplay   string   `json:"totalDisplay"`
	Subtotal       string   `json:"subtotal"`
	SubtotalDisplay string  `json:"subtotalDisplay"`
	Recipient      Customer `json:"recipient"`
	QuoteUrl       string   `json:"quoteUrl"`
	Creator        string   `json:"creator"`
	UpdatedBy      string   `json:"updatedBy"`
	Reason         string   `json:"Reason"`
	Items          []Item   `json:"items"`
}

type SlackMessage struct {
	Text   string  `json:"text,omitempty"`
	Blocks []Block `json:"blocks,omitempty"`
}

type Block struct {
	Type string     `json:"type"`
	Text *BlockText `json:"text,omitempty"`
}

type BlockText struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	http.HandleFunc("/", healthHandler)
	http.HandleFunc("/webhooks/fastspring", webhookHandler)

	log.Printf("Starting server on port %s", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}

func webhookHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("Error reading body: %v", err)
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// Verify HMAC signature if secret is configured
	hmacSecret := os.Getenv("FASTSPRING_HMAC_SECRET")
	if hmacSecret != "" {
		signature := r.Header.Get("X-FS-Signature")
		if !verifyHMAC(body, signature, hmacSecret) {
			log.Printf("Invalid HMAC signature")
			http.Error(w, "Invalid signature", http.StatusUnauthorized)
			return
		}
	}

	var payload WebhookPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		log.Printf("Error parsing JSON: %v", err)
		sendErrorNotification("Failed to parse webhook payload", err.Error())
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	var processingErrors []string
	for _, event := range payload.Events {
		if err := processEvent(event); err != nil {
			log.Printf("Error processing event %s: %v", event.ID, err)
			processingErrors = append(processingErrors, fmt.Sprintf("Event %s (%s): %v", event.ID, event.Type, err))
		}
	}

	if len(processingErrors) > 0 {
		sendErrorNotification("Failed to process webhook events", strings.Join(processingErrors, "\n"))
		http.Error(w, "Failed to process some events", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}

func verifyHMAC(body []byte, signature string, secret string) bool {
	if signature == "" {
		return false
	}

	// Fastspring sends base64-encoded HMAC-SHA256 signature
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	expectedMAC := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	return hmac.Equal([]byte(signature), []byte(expectedMAC))
}

func processEvent(event Event) error {
	log.Printf("Processing event: type=%s id=%s live=%v", event.Type, event.ID, event.Live)

	switch event.Type {
	// Order events
	case "order.completed":
		return handleOrderEvent(event, "Order completed", "success")
	case "order.canceled":
		return handleOrderEvent(event, "Order canceled", "warning")
	case "order.failed":
		return handleOrderEvent(event, "Order failed", "error")
	case "order.payment.pending":
		return handleOrderEvent(event, "Payment pending", "warning")
	case "order.approval.pending":
		return handleOrderEvent(event, "Approval pending", "warning")

	// Return events
	case "return.created":
		return handleReturnEvent(event)

	// Subscription lifecycle events
	case "subscription.activated":
		return handleSubscriptionEvent(event, "Subscription activated", "success")
	case "subscription.deactivated":
		return handleSubscriptionEvent(event, "Subscription deactivated", "error")
	case "subscription.canceled":
		return handleSubscriptionEvent(event, "Subscription canceled", "warning")
	case "subscription.uncanceled":
		return handleSubscriptionEvent(event, "Subscription uncanceled", "success")
	case "subscription.updated":
		return handleSubscriptionEvent(event, "Subscription updated", "info")
	case "subscription.paused":
		return handleSubscriptionEvent(event, "Subscription paused", "warning")
	case "subscription.resumed":
		return handleSubscriptionEvent(event, "Subscription resumed", "success")

	// Subscription payment events
	case "subscription.charge.completed":
		return handleSubscriptionChargeEvent(event, "Subscription payment received", "success")
	case "subscription.charge.failed":
		return handleSubscriptionChargeEvent(event, "Subscription payment failed", "error")

	// Subscription reminder events
	case "subscription.trial.reminder":
		return handleSubscriptionEvent(event, "Trial ending soon", "warning")
	case "subscription.payment.reminder":
		return handleSubscriptionEvent(event, "Payment reminder", "info")
	case "subscription.payment.overdue":
		return handleSubscriptionEvent(event, "Payment overdue", "error")

	// Invoice events
	case "invoice.reminder.email":
		return handleOrderEvent(event, "Invoice reminder sent", "info")

	// Quote events
	case "quote.created":
		return handleQuoteEvent(event, "Quote created")
	case "quote.updated":
		return handleQuoteEvent(event, "Quote updated")

	default:
		log.Printf("Unhandled event type: %s", event.Type)
		return nil
	}
}

func handleOrderEvent(event Event, title string, severity string) error {
	var data OrderData
	if err := json.Unmarshal(event.Data, &data); err != nil {
		return fmt.Errorf("failed to parse order data: %w", err)
	}

	message := formatOrderMessage(data, event.Live, title, severity)
	return sendSlackNotification(message)
}

func handleSubscriptionEvent(event Event, title string, severity string) error {
	var data SubscriptionData
	if err := json.Unmarshal(event.Data, &data); err != nil {
		return fmt.Errorf("failed to parse subscription data: %w", err)
	}

	message := formatSubscriptionMessage(data, event.Live, title, severity)
	return sendSlackNotification(message)
}

func handleSubscriptionChargeEvent(event Event, title string, severity string) error {
	var data SubscriptionData
	if err := json.Unmarshal(event.Data, &data); err != nil {
		return fmt.Errorf("failed to parse subscription charge data: %w", err)
	}

	message := formatSubscriptionChargeMessage(data, event.Live, title, severity)
	return sendSlackNotification(message)
}

func handleReturnEvent(event Event) error {
	var data ReturnData
	if err := json.Unmarshal(event.Data, &data); err != nil {
		return fmt.Errorf("failed to parse return data: %w", err)
	}

	message := formatReturnMessage(data, event.Live)
	return sendSlackNotification(message)
}

func handleQuoteEvent(event Event, title string) error {
	var data QuoteData
	if err := json.Unmarshal(event.Data, &data); err != nil {
		return fmt.Errorf("failed to parse quote data: %w", err)
	}

	message := formatQuoteMessage(data, event.Live, title)
	return sendSlackNotification(message)
}

func severityEmoji(severity string) string {
	switch severity {
	case "success":
		return "white_check_mark"
	case "warning":
		return "warning"
	case "error":
		return "x"
	case "info":
		return "information_source"
	default:
		return "bell"
	}
}

func formatOrderMessage(data OrderData, live bool, title string, severity string) SlackMessage {
	emoji := severityEmoji(severity)

	items := ""
	for _, item := range data.Items {
		items += fmt.Sprintf("• %s (x%v) - %s\n", item.Display, item.Quantity, formatCurrency(item.Subtotal, data.Currency))
	}

	text := fmt.Sprintf(":%s: %s\n\nCustomer: %s %s (%s)\nCompany: %s\nOrder: %s\nTotal: %s",
		emoji,
		title,
		data.Customer.First,
		data.Customer.Last,
		data.Customer.Email,
		data.Customer.Company,
		data.Reference,
		data.TotalDisplay,
	)

	if items != "" {
		text += fmt.Sprintf("\n\nItems:\n%s", items)
	}

	return SlackMessage{Text: text}
}

func formatSubscriptionMessage(data SubscriptionData, live bool, title string, severity string) SlackMessage {
	emoji := severityEmoji(severity)

	text := fmt.Sprintf(":%s: %s\n\nCustomer: %s %s (%s)\nSubscription: %s\nProduct: %s",
		emoji,
		title,
		data.Customer.First,
		data.Customer.Last,
		data.Customer.Email,
		data.Subscription,
		data.Product,
	)

	if data.NextDate != "" {
		text += fmt.Sprintf("\nNext billing: %s", data.NextDate)
	}
	if data.EndDate != "" {
		text += fmt.Sprintf("\nEnds: %s", data.EndDate)
	}

	return SlackMessage{Text: text}
}

func formatSubscriptionChargeMessage(data SubscriptionData, live bool, title string, severity string) SlackMessage {
	emoji := severityEmoji(severity)

	text := fmt.Sprintf(":%s: %s\n\nCustomer: %s %s (%s)\nSubscription: %s\nAmount: %s",
		emoji,
		title,
		data.Customer.First,
		data.Customer.Last,
		data.Customer.Email,
		data.Subscription,
		data.TotalDisplay,
	)

	if data.NextDate != "" {
		text += fmt.Sprintf("\nNext billing: %s", data.NextDate)
	}

	return SlackMessage{Text: text}
}

func formatReturnMessage(data ReturnData, live bool) SlackMessage {
	text := fmt.Sprintf(":rotating_light: Refund processed\n\nCustomer: %s %s (%s)\nOrder: %s\nAmount: %s\nReason: %s",
		data.Customer.First,
		data.Customer.Last,
		data.Customer.Email,
		data.OrderID,
		data.TotalDisplay,
		data.Reason,
	)

	return SlackMessage{Text: text}
}

func formatQuoteMessage(data QuoteData, live bool, title string) SlackMessage {
	text := fmt.Sprintf(":memo: %s\n\nQuote: %s (%s)\nTotal: %s\nStatus: %s",
		title,
		data.QuoteName,
		data.Quote,
		data.TotalDisplay,
		data.QuoteStatus,
	)

	// Add recipient info
	if data.Recipient.Email != "" {
		text += fmt.Sprintf("\nRecipient: %s %s (%s)", data.Recipient.First, data.Recipient.Last, data.Recipient.Email)
	}
	if data.Recipient.Company != "" {
		text += fmt.Sprintf("\nCompany: %s", data.Recipient.Company)
	}

	// Add items
	if len(data.Items) > 0 {
		text += "\n\nItems:"
		for _, item := range data.Items {
			subtotalStr := fmt.Sprintf("%v", item.Subtotal)
			if item.SubtotalDisplay != "" {
				subtotalStr = item.SubtotalDisplay
			}
			text += fmt.Sprintf("\n• %s (x%v) - %s", item.Display, item.Quantity, subtotalStr)
		}
	}

	if data.Reason != "" {
		text += fmt.Sprintf("\n\nReason: %s", data.Reason)
	}

	return SlackMessage{Text: text}
}

func formatCurrency(amount any, currency string) string {
	return fmt.Sprintf("%s %v", currency, amount)
}

func sendSlackNotification(message SlackMessage) error {
	webhookURL := os.Getenv("SLACK_WEBHOOK_URL")
	if webhookURL == "" {
		log.Printf("SLACK_WEBHOOK_URL not set, skipping notification")
		log.Printf("Would have sent: %s", message.Text)
		return nil
	}

	payload, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to marshal slack message: %w", err)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(webhookURL, "application/json", bytes.NewBuffer(payload))
	if err != nil {
		return fmt.Errorf("failed to send slack notification: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("slack returned status %d: %s", resp.StatusCode, string(body))
	}

	log.Printf("Slack notification sent successfully")
	return nil
}

func sendErrorNotification(title string, details string) {
	message := SlackMessage{
		Text: fmt.Sprintf(":rotating_light: *%s*\n\n```%s```", title, details),
	}

	if err := sendSlackNotification(message); err != nil {
		log.Printf("Failed to send error notification to Slack: %v", err)
	}
}
