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

type SubscriptionChargeData struct {
	Order            string `json:"order"`
	Subscription     string `json:"subscription"`
	Account          string `json:"account"`
	Quote            string `json:"quote"`
	Currency         string `json:"currency"`
	Total            any    `json:"total"`
	Status           string `json:"status"`
	Reason           string `json:"reason"`
	Sequence         int    `json:"sequence"`
	TimestampDisplay string `json:"timestampDisplay"`
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

type InvoiceData struct {
	ID             string   `json:"id"`
	OrderReference string   `json:"orderReference"`
	DueDate        string   `json:"dueDate"`
	Subtotal       any      `json:"subtotal"`
	Currency       string   `json:"currency"`
	Contact        Customer `json:"contact"`
	Items          []Item   `json:"items"`
	InvoiceUrl     string   `json:"invoiceUrl"`
	Account        string   `json:"account"`
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

// Fastspring API response types (for digest)

type SubscriptionListResponse struct {
	Action        string               `json:"action"`
	Result        string               `json:"result"`
	NextPage      *int                 `json:"nextPage"`
	Subscriptions []SubscriptionDetail `json:"subscriptions"`
}

type SubscriptionDetail struct {
	ID           string `json:"id"`
	Subscription string `json:"subscription"`
	Active       bool   `json:"active"`
	State        string `json:"state"`
	Product      string `json:"product"`
	Display      string `json:"display"`
	Currency     string `json:"currency"`
	Price        any    `json:"price"`
	Quantity     any    `json:"quantity"`
	Account      any    `json:"account"` // Can be string (ID) or object
	Begin        any    `json:"begin"`
	BeginDisplay string `json:"beginDisplay"`
	Live         bool   `json:"live"`
}

type SubscriptionAccount struct {
	ID      string         `json:"id"`
	Account string         `json:"account"`
	Contact AccountContact `json:"contact"`
}

type AccountContact struct {
	First   string `json:"first"`
	Last    string `json:"last"`
	Email   string `json:"email"`
	Company string `json:"company"`
	Phone   string `json:"phone"`
}

type SubscriptionEntry struct {
	ID              string `json:"id"`
	BeginPeriodDate string `json:"beginPeriodDate"`
	EndPeriodDate   string `json:"endPeriodDate"`
	Order           any    `json:"order"` // Can be string or object
	Reference       string `json:"reference"`
	Completed       bool   `json:"completed"`
	ChangedDisplay  string `json:"changedDisplay"`
	Live            bool   `json:"live"`
	Currency        string `json:"currency"`
	Total           any    `json:"total"`
	TotalDisplay    string `json:"totalDisplay"`
	Subtotal        any    `json:"subtotal"`
	SubtotalDisplay string `json:"subtotalDisplay"`
	Tax             any    `json:"tax"`
	TaxDisplay      string `json:"taxDisplay"`
}

type CustomerDigest struct {
	AccountID string
	Contact   AccountContact
	Subs      []SubDigest
}

type SubDigest struct {
	SubscriptionID string
	Product        string
	Display        string
	Currency       string
	Entries        []SubscriptionEntry
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
	http.HandleFunc("/digest", digestHandler)

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
		return handleInvoiceEvent(event, "Invoice reminder sent")

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
	var data SubscriptionChargeData
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

func handleInvoiceEvent(event Event, title string) error {
	var data InvoiceData
	if err := json.Unmarshal(event.Data, &data); err != nil {
		return fmt.Errorf("failed to parse invoice data: %w", err)
	}

	message := formatInvoiceMessage(data, event.Live, title)
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

func formatSubscriptionChargeMessage(data SubscriptionChargeData, live bool, title string, severity string) SlackMessage {
	emoji := severityEmoji(severity)

	text := fmt.Sprintf(":%s: %s\n\nSubscription: %s",
		emoji,
		title,
		data.Subscription,
	)

	if data.Order != "" {
		text += fmt.Sprintf("\nOrder: %s", data.Order)
	}
	if data.Total != nil {
		text += fmt.Sprintf("\nAmount: %s", formatAnyAmount(data.Total, data.Currency))
	}
	if data.Sequence > 0 {
		text += fmt.Sprintf("\nPayment #%d", data.Sequence)
	}
	if data.Reason != "" {
		text += fmt.Sprintf("\nReason: %s", data.Reason)
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

func formatInvoiceMessage(data InvoiceData, live bool, title string) SlackMessage {
	text := fmt.Sprintf(":page_facing_up: %s\n\nCustomer: %s %s (%s)",
		title,
		data.Contact.First,
		data.Contact.Last,
		data.Contact.Email,
	)

	if data.Contact.Company != "" {
		text += fmt.Sprintf("\nCompany: %s", data.Contact.Company)
	}

	text += fmt.Sprintf("\nOrder: %s\nDue: %s\nAmount: %s",
		data.OrderReference,
		data.DueDate,
		formatAnyAmount(data.Subtotal, data.Currency),
	)

	// Add items
	if len(data.Items) > 0 {
		text += "\n\nItems:"
		for _, item := range data.Items {
			text += fmt.Sprintf("\n• %s (x%v)", item.Display, item.Quantity)
		}
	}

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
			subtotalStr := item.SubtotalDisplay
			if subtotalStr == "" {
				subtotalStr = formatAnyAmount(item.Subtotal, data.QuoteCurrency)
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

func formatAnyAmount(amount any, currency string) string {
	switch v := amount.(type) {
	case float64:
		if currency != "" {
			return fmt.Sprintf("%s %.2f", currency, v)
		}
		return fmt.Sprintf("%.2f", v)
	case string:
		if currency != "" && v != "" {
			return fmt.Sprintf("%s %s", currency, v)
		}
		return v
	default:
		if currency != "" {
			return fmt.Sprintf("%s %v", currency, amount)
		}
		return fmt.Sprintf("%v", amount)
	}
}

// Fastspring API client

func fastspringAPIRequest(method, path string, body io.Reader) (*http.Response, error) {
	username := os.Getenv("FASTSPRING_API_USERNAME")
	password := os.Getenv("FASTSPRING_API_PASSWORD")

	url := "https://api.fastspring.com" + path

	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.SetBasicAuth(username, password)
	req.Header.Set("User-Agent", "fastspring-slack-bridge/1.0")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	client := &http.Client{Timeout: 30 * time.Second}
	return client.Do(req)
}

func fetchAllSubscriptions() ([]SubscriptionDetail, error) {
	var allSubs []SubscriptionDetail
	page := 1

	for {
		// Fetch all subscriptions (active, canceled, deactivated, etc.)
		path := fmt.Sprintf("/subscriptions?scope=live&page=%d&limit=50", page)
		resp, err := fastspringAPIRequest("GET", path, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to list subscriptions page %d: %w", page, err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			return nil, fmt.Errorf("subscriptions list returned %d: %s", resp.StatusCode, string(body))
		}

		bodyBytes, _ := io.ReadAll(resp.Body)

		var result SubscriptionListResponse
		if err := json.Unmarshal(bodyBytes, &result); err != nil {
			return nil, fmt.Errorf("failed to decode subscriptions list: %w", err)
		}

		log.Printf("Fetched %d subscriptions from page %d", len(result.Subscriptions), page)
		allSubs = append(allSubs, result.Subscriptions...)

		if result.NextPage == nil || *result.NextPage == 0 {
			break
		}
		page = *result.NextPage
	}

	return allSubs, nil
}

type QuoteListResponse struct {
	Embedded struct {
		Quotes []QuoteAPIData `json:"quotes"`
	} `json:"_embedded"`
}

type QuoteAPIData struct {
	ID            string  `json:"id"`
	Quote         string  `json:"quote"`
	Name          string  `json:"name"`
	Status        string  `json:"status"`
	Currency      string  `json:"currency"`
	Total         any     `json:"total"`
	TotalDisplay  string  `json:"totalDisplay"`
	Created       string  `json:"created"`
	Expires       string  `json:"expires"`
	Recipient     any     `json:"recipient"`
	QuoteUrl      string  `json:"quoteUrl"`
}

func fetchRecentQuotes() ([]QuoteAPIData, error) {
	// Fetch open and awaiting payment quotes
	path := "/quotes?statuses=OPEN&statuses=AWAITING_PAYMENT"
	resp, err := fastspringAPIRequest("GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch quotes: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("quotes list returned %d: %s", resp.StatusCode, string(body))
	}

	bodyBytes, _ := io.ReadAll(resp.Body)

	var result QuoteListResponse
	if err := json.Unmarshal(bodyBytes, &result); err != nil {
		return nil, fmt.Errorf("failed to decode quotes list: %w", err)
	}

	log.Printf("Fetched %d quotes", len(result.Embedded.Quotes))
	return result.Embedded.Quotes, nil
}

func fetchSubscriptionEntries(subscriptionID string) ([]SubscriptionEntry, error) {
	path := fmt.Sprintf("/subscriptions/%s/entries", subscriptionID)
	resp, err := fastspringAPIRequest("GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch entries for %s: %w", subscriptionID, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("entries for %s returned %d: %s", subscriptionID, resp.StatusCode, string(body))
	}

	bodyBytes, _ := io.ReadAll(resp.Body)

	var entries []SubscriptionEntry
	if err := json.Unmarshal(bodyBytes, &entries); err != nil {
		return nil, fmt.Errorf("failed to decode entries for %s: %w", subscriptionID, err)
	}

	return entries, nil
}

// Weekly digest

func getAccountID(account any) string {
	switch v := account.(type) {
	case string:
		return v
	case map[string]any:
		if id, ok := v["id"].(string); ok && id != "" {
			return id
		}
		if acc, ok := v["account"].(string); ok {
			return acc
		}
	}
	return ""
}

func getAccountContact(account any) AccountContact {
	if m, ok := account.(map[string]any); ok {
		if contact, ok := m["contact"].(map[string]any); ok {
			return AccountContact{
				First:   getStringField(contact, "first"),
				Last:    getStringField(contact, "last"),
				Email:   getStringField(contact, "email"),
				Company: getStringField(contact, "company"),
				Phone:   getStringField(contact, "phone"),
			}
		}
	}
	return AccountContact{}
}

func getStringField(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

// Extract total/currency from entry's nested order object
func getEntryTotal(e SubscriptionEntry) string {
	if order, ok := e.Order.(map[string]any); ok {
		if totalDisplay, ok := order["totalDisplay"].(string); ok && totalDisplay != "" {
			return totalDisplay
		}
		if total, ok := order["total"].(float64); ok {
			currency := ""
			if c, ok := order["currency"].(string); ok {
				currency = c
			}
			return formatAnyAmount(total, currency)
		}
	}
	// Fallback to entry-level fields
	if e.TotalDisplay != "" {
		return e.TotalDisplay
	}
	return formatAnyAmount(e.Total, e.Currency)
}

func getEntryCompleted(e SubscriptionEntry) bool {
	if order, ok := e.Order.(map[string]any); ok {
		if completed, ok := order["completed"].(bool); ok {
			return completed
		}
	}
	return e.Completed
}

func getEntryCustomer(e SubscriptionEntry) AccountContact {
	if order, ok := e.Order.(map[string]any); ok {
		if customer, ok := order["customer"].(map[string]any); ok {
			return AccountContact{
				First:   getStringField(customer, "first"),
				Last:    getStringField(customer, "last"),
				Email:   getStringField(customer, "email"),
				Company: getStringField(customer, "company"),
				Phone:   getStringField(customer, "phone"),
			}
		}
	}
	return AccountContact{}
}

func getEntryAccountID(e SubscriptionEntry) string {
	if order, ok := e.Order.(map[string]any); ok {
		if account, ok := order["account"].(string); ok {
			return account
		}
	}
	return ""
}

func getEntryInvoiceUrl(e SubscriptionEntry) string {
	if order, ok := e.Order.(map[string]any); ok {
		if url, ok := order["invoiceUrl"].(string); ok {
			return url
		}
	}
	return ""
}

func getEntryDate(e SubscriptionEntry) string {
	if order, ok := e.Order.(map[string]any); ok {
		// Prefer the ISO date for consistent comparison
		if date, ok := order["changedDisplayISO8601"].(string); ok && date != "" {
			return date
		}
		if date, ok := order["changedDisplay"].(string); ok && date != "" {
			return date
		}
	}
	if e.ChangedDisplay != "" {
		return e.ChangedDisplay
	}
	return e.BeginPeriodDate
}

// deduplicateEntries removes pending entries if there's a completed entry for the same date
func deduplicateEntries(entries []SubscriptionEntry) []SubscriptionEntry {
	// First pass: collect dates that have completed entries
	completedDates := make(map[string]bool)
	for _, e := range entries {
		if getEntryCompleted(e) {
			date := getEntryDate(e)
			completedDates[date] = true
		}
	}

	// Second pass: filter out pending entries for dates that have completed ones
	var result []SubscriptionEntry
	for _, e := range entries {
		date := getEntryDate(e)
		if !getEntryCompleted(e) && completedDates[date] {
			// Skip this pending entry - there's a completed one for the same date
			continue
		}
		result = append(result, e)
	}

	return result
}

func digestHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	log.Printf("Starting weekly payment digest generation")

	// 1. Fetch all subscriptions (includes details)
	subscriptions, err := fetchAllSubscriptions()
	if err != nil {
		log.Printf("Error fetching subscriptions: %v", err)
		sendErrorNotification("Digest: failed to fetch subscriptions", err.Error())
		http.Error(w, "Failed to fetch subscriptions", http.StatusInternalServerError)
		return
	}

	log.Printf("Found %d subscriptions", len(subscriptions))

	if len(subscriptions) == 0 {
		log.Printf("No subscriptions found, skipping digest")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("no active subscriptions"))
		return
	}

	// 2. Fetch entries for each subscription
	type subWithEntries struct {
		Detail  SubscriptionDetail
		Entries []SubscriptionEntry
	}
	var allSubs []subWithEntries

	for _, sub := range subscriptions {
		entries, err := fetchSubscriptionEntries(sub.ID)
		if err != nil {
			log.Printf("Error fetching entries for %s: %v", sub.ID, err)
			continue
		}

		// Take first 5 entries (API returns most recent first)
		if len(entries) > 5 {
			entries = entries[:5]
		}

		allSubs = append(allSubs, subWithEntries{Detail: sub, Entries: entries})

		// Rate limiting: stay under 250 req/min
		time.Sleep(300 * time.Millisecond)
	}

	// 3. Group by account/customer
	customerMap := make(map[string]*CustomerDigest)
	var customerOrder []string
	for _, s := range allSubs {
		// Try to get account ID from subscription, then from first entry's order
		accountID := getAccountID(s.Detail.Account)
		if accountID == "" && len(s.Entries) > 0 {
			accountID = getEntryAccountID(s.Entries[0])
		}
		if accountID == "" {
			accountID = s.Detail.ID // fallback to subscription ID
		}

		cd, exists := customerMap[accountID]
		if !exists {
			// Try to get contact from subscription, then from first entry's order
			contact := getAccountContact(s.Detail.Account)
			if contact.Email == "" && len(s.Entries) > 0 {
				contact = getEntryCustomer(s.Entries[0])
			}
			cd = &CustomerDigest{
				AccountID: accountID,
				Contact:   contact,
			}
			customerMap[accountID] = cd
			customerOrder = append(customerOrder, accountID)
		}

		productName := s.Detail.Display
		if productName == "" {
			productName = s.Detail.Product
		}

		cd.Subs = append(cd.Subs, SubDigest{
			SubscriptionID: s.Detail.ID,
			Product:        s.Detail.Product,
			Display:        productName,
			Currency:       s.Detail.Currency,
			Entries:        s.Entries,
		})
	}

	// 4. Fetch recent quotes
	quotes, err := fetchRecentQuotes()
	if err != nil {
		log.Printf("Error fetching quotes: %v", err)
		// Don't fail the whole digest, just log and continue
		quotes = nil
	}
	log.Printf("Found %d recent quotes", len(quotes))

	// 5. Format and send Slack message
	if err := sendDigestToSlack(customerMap, customerOrder, quotes); err != nil {
		log.Printf("Error sending digest to Slack: %v", err)
		sendErrorNotification("Digest: failed to send to Slack", err.Error())
		http.Error(w, "Failed to send digest", http.StatusInternalServerError)
		return
	}

	log.Printf("Weekly digest sent successfully (%d customers, %d subscriptions)",
		len(customerMap), len(allSubs))
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("digest sent"))
}

func sendDigestToSlack(customers map[string]*CustomerDigest, order []string, quotes []QuoteAPIData) error {
	message := formatDigestMessage(customers, order, quotes)

	// Slack supports up to 40,000 chars, but for readability split at ~10k
	if len(message.Text) <= 10000 {
		return sendSlackNotification(message)
	}

	// If too long, send header + quotes first, then customers in batches
	header := fmt.Sprintf(":bar_chart: *Weekly Payment Digest* — %s\n\n*%d customers* with subscriptions",
		time.Now().Format("Jan 2, 2006"), len(customers))

	// Add quotes to header if any
	if len(quotes) > 0 {
		header += "\n\n" + formatQuotesSection(quotes)
	}

	if err := sendSlackNotification(SlackMessage{Text: header}); err != nil {
		return err
	}

	// Send customers in batches to avoid hitting limits
	var batch strings.Builder
	for i, accountID := range order {
		cd := customers[accountID]
		section := formatCustomerSection(cd)

		if batch.Len()+len(section) > 8000 {
			// Send current batch and start new one
			if err := sendSlackNotification(SlackMessage{Text: batch.String()}); err != nil {
				log.Printf("Failed to send digest batch: %v", err)
			}
			batch.Reset()
		}

		if i > 0 && batch.Len() > 0 {
			batch.WriteString("\n\n")
		}
		batch.WriteString(section)
	}

	// Send remaining batch
	if batch.Len() > 0 {
		if err := sendSlackNotification(SlackMessage{Text: batch.String()}); err != nil {
			log.Printf("Failed to send final digest batch: %v", err)
		}
	}

	return nil
}

func formatDigestMessage(customers map[string]*CustomerDigest, order []string, quotes []QuoteAPIData) SlackMessage {
	now := time.Now()
	text := fmt.Sprintf(":bar_chart: *Weekly Payment Digest* — %s\n\n*%d customers* with subscriptions\n",
		now.Format("Jan 2, 2006"), len(customers))

	for _, accountID := range order {
		cd := customers[accountID]
		text += "\n" + formatCustomerSection(cd)
	}

	// Add quotes section
	if len(quotes) > 0 {
		text += "\n\n" + formatQuotesSection(quotes)
	}

	return SlackMessage{Text: text}
}

func formatCustomerDigestMessage(cd *CustomerDigest) SlackMessage {
	return SlackMessage{Text: formatCustomerSection(cd)}
}

func formatCustomerSection(cd *CustomerDigest) string {
	name := strings.TrimSpace(cd.Contact.First + " " + cd.Contact.Last)
	if name == "" {
		name = cd.Contact.Email
	}

	section := fmt.Sprintf(":bust_in_silhouette: *%s*", name)
	if cd.Contact.Company != "" {
		section += fmt.Sprintf(" (%s)", cd.Contact.Company)
	}
	if cd.Contact.Email != "" {
		section += fmt.Sprintf("\n      %s", cd.Contact.Email)
	}

	for _, sub := range cd.Subs {
		section += fmt.Sprintf("\n\n      :package: %s", sub.Display)

		if len(sub.Entries) == 0 {
			section += "\n            _No payment entries_"
			continue
		}

		// Deduplicate: remove pending entries if completed exists for same date
		entries := deduplicateEntries(sub.Entries)

		for _, e := range entries {
			status := ":white_check_mark:"
			if !getEntryCompleted(e) {
				status = ":hourglass_flowing_sand:"
			}

			amount := getEntryTotal(e)
			date := getEntryDate(e)
			invoiceUrl := getEntryInvoiceUrl(e)

			if invoiceUrl != "" {
				section += fmt.Sprintf("\n            %s  <%s|%s>  •  %s", status, invoiceUrl, date, amount)
			} else {
				section += fmt.Sprintf("\n            %s  %s  •  %s", status, date, amount)
			}
		}
	}

	return section
}

func formatQuotesSection(quotes []QuoteAPIData) string {
	section := ":memo: *Recent Quotes* (last 30 days)\n"

	for _, q := range quotes {
		statusEmoji := ":hourglass_flowing_sand:"
		switch strings.ToUpper(q.Status) {
		case "OPEN":
			statusEmoji = ":hourglass_flowing_sand:"
		case "ACCEPTED":
			statusEmoji = ":white_check_mark:"
		case "CANCELED", "EXPIRED":
			statusEmoji = ":x:"
		}

		name := q.Name
		if name == "" {
			name = q.Quote
		}

		total := q.TotalDisplay
		if total == "" {
			total = formatAnyAmount(q.Total, q.Currency)
		}

		// Get recipient info
		recipientName := ""
		if recipient, ok := q.Recipient.(map[string]any); ok {
			first := getStringField(recipient, "first")
			last := getStringField(recipient, "last")
			recipientName = strings.TrimSpace(first + " " + last)
			if recipientName == "" {
				recipientName = getStringField(recipient, "email")
			}
		}

		section += fmt.Sprintf("\n%s  *%s*  •  %s", statusEmoji, name, total)
		if recipientName != "" {
			section += fmt.Sprintf("  •  %s", recipientName)
		}
		section += fmt.Sprintf("  •  _%s_", q.Status)
	}

	return section
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
