package main

import (
    "encoding/base64"
    "net/url"
    "strings"
)

// EncodePayload এনকোডিং মেকানিজম অনুযায়ী পেলোড এনকোড করে
func EncodePayload(payload, encoding string) string {
    switch strings.ToLower(encoding) {
    case "url":
        return url.QueryEscape(payload)
    case "base64":
        return base64.StdEncoding.EncodeToString([]byte(payload))
    default:
        return payload // যদি অজানা এনকোডিং হয়, তাহলে পেলোড অপরিবর্তিত রাখে
    }
}