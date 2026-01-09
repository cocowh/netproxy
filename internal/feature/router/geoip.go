package router

import (
	"net"
	"strings"

	"github.com/oschwald/geoip2-golang"
)

// GeoIPMatcher matches IP addresses against a GeoIP database
type GeoIPMatcher struct {
	reader      *geoip2.Reader
	countryCode string
}

// NewGeoIPMatcher creates a new GeoIPMatcher
func NewGeoIPMatcher(reader *geoip2.Reader, countryCode string) *GeoIPMatcher {
	return &GeoIPMatcher{
		reader:      reader,
		countryCode: strings.ToUpper(countryCode),
	}
}

// Match checks if the IP belongs to the configured country
func (m *GeoIPMatcher) Match(ip net.IP) bool {
	if m.reader == nil || ip == nil {
		return false
	}

	record, err := m.reader.Country(ip)
	if err != nil {
		return false
	}

	return record.Country.IsoCode == m.countryCode
}
