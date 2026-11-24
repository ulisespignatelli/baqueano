package intel

import "testing"

func TestCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"2.4.49", "2.4.50", -1}, {"2.4.9", "2.4.10", -1}, {"1.18.0", "1.18", 0},
		{"8.9p1", "9.8p1", -1}, {"8.5p1", "8.5", 1}, {"9.7p1", "9.8p1", -1}, {"8.9p1", "8.9p2", -1},
		{"9.0.0.M1", "9.0.0", -1}, {"9.0.0.M1", "9.0.0.M10", -1}, {"2.0-rc1", "2.0", -1}, {"2.0beta2", "2.0rc1", -1},
		{"10.2.9-h1", "10.2.9", 1}, {"10.2.9-h1", "10.2.10", -1}, {"5.18.2", "5.18.3", -1}, {"16.1.2.2", "16.1.2", 1},
		{"7.4.33", "7.4.33", 0}, {"0", "1.0", -1},
	}
	for _, c := range cases {
		if got := Compare(c.a, c.b); got != c.want {
			t.Errorf("Compare(%q,%q) = %d, quería %d", c.a, c.b, got, c.want)
		}
		if got := Compare(c.b, c.a); got != -c.want {
			t.Errorf("no es antisimétrico: Compare(%q,%q) = %d", c.b, c.a, got)
		}
	}
}

func TestRange(t *testing.T) {
	regre := Range{Start: "8.5p1", StartInc: true, End: "9.8p1"}
	for v, want := range map[string]bool{"8.5p1": true, "8.9p1": true, "9.7p1": true, "9.8p1": false, "7.4p1": false, "8.4p1": false} {
		if regre.Contains(v) != want {
			t.Errorf("%s en %s: quería %v", v, regre, want)
		}
	}
	branch := Range{Prefix: "7.1", End: "7.1.33"}
	for v, want := range map[string]bool{"7.1.32": true, "7.1.33": false, "7.10.1": false, "7.2.1": false} {
		if branch.Contains(v) != want {
			t.Errorf("%s en %s: quería %v", v, branch, want)
		}
	}
	if (Range{}).Contains("1.0") {
		t.Error("un tramo vacío no debe contener nada")
	}
}
