package godates

import "time"

var countryTz = map[string]string{
	"Rome": "Europe/Rome",
}

var DateLayout string = "2006-01-02 15:04:05"
var CompactDateLayout string = "20060102150405"

func TimeIn(name string, utcTime time.Time) (time.Time, error) {
	loc, err := time.LoadLocation(countryTz[name])
	if err != nil {
		return time.Time{}, err
	}
	return utcTime.In(loc), nil
}

func CompareDates(t1 time.Time, t2 time.Time) bool {
	return t1.Truncate(24 * time.Hour).Equal(t2.Truncate(24 * time.Hour))
}
