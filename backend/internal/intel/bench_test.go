package intel

import "testing"

// TestBenchmark corre el benchmark de precision en cada build: si un cambio produce un descarte
// peligroso o baja la precision, el CI falla.
func TestBenchmark(t *testing.T) {
	c, db, err := LoadBench("../../../bench")
	if err != nil {
		t.Fatal(err)
	}
	r := RunBench(c, db)
	for _, x := range r.Cases {
		if x.Outcome != "acierto" {
			t.Logf("%-20s %s %s %s → %s: %s", x.Outcome, x.Product, x.Version, x.CVE, x.Confidence, x.Reason)
		}
	}
	t.Logf("precisión %.2f (sin verificar %.2f), recall %.2f, falsos positivos %d, descartes peligrosos %d, pendientes %d",
		r.Precision(), r.BaselinePrecision(), r.Recall(), r.FP, r.FNHard, r.Pending)
	if r.FNHard > 0 {
		t.Errorf("hay %d descartes peligrosos: CVE que afectan al servicio y el motor descartó", r.FNHard)
	}
	if r.Precision() < 0.9 {
		t.Errorf("precisión %.2f, por debajo de 0.90", r.Precision())
	}
}
