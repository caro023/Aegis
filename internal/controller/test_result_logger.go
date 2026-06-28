package controller

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// resultsDir è la cartella fissa dove vengono scritti i risultati dei test.
const resultsDir = "/mnt/c/Users/ferra/Desktop/tesi2/intents/Kubeteus/microservices-demo/release/Kubeteus/results"

const (
	passedFile  = "passed.txt"
	failedFile  = "failed.txt"
	skippedFile = "skipped.txt"
)

// resultLogMu protegge le scritture concorrenti sui file, dato che processIntent
// può girare su più worker/goroutine contemporaneamente.
var resultLogMu sync.Mutex

// TestOutcome rappresenta l'esito sintetico di un test di connettività,
// usato per decidere su quale file scrivere il record.
type TestOutcome int

const (
	OutcomePassed TestOutcome = iota
	OutcomeFailed
	OutcomeSkipped
)

// classifyTestOutput determina l'esito a partire dall'output dello script di
// test e da un eventuale errore di esecuzione (non nil quando il controller
// ha già deciso che il test è FALLITO, es. tester.RunTestScript ha ritornato err).
//
// Riconosce i casi SKIP cercando il prefisso "SKIP" prodotto dagli script
// generati da TEST_GENERATOR_PROMPT (es. "SKIP: source pod not found...",
// "SKIP: devtcp does not support UDP", ecc.), così da non confonderli con un
// vero PASS nelle statistiche finali.
func classifyTestOutput(output string, runErr error) TestOutcome {
	trimmed := strings.TrimSpace(output)

	// Un test SKIP esce sempre con codice 0 (quindi runErr è nil) e stampa
	// una riga che inizia con "SKIP". Va controllato PRIMA del caso PASS,
	// altrimenti finirebbe in OutcomePassed solo perché runErr == nil.
	if strings.HasPrefix(trimmed, "SKIP") || strings.Contains(trimmed, "\nSKIP") {
		return OutcomeSkipped
	}

	if runErr != nil {
		return OutcomeFailed
	}

	return OutcomePassed
}

// PolicyYAMLProvider è l'interfaccia minima richiesta per estrarre lo YAML
// dalle policy generate, indipendentemente dal tipo concreto usato in
// utils.Policy (così questo file non introduce un import circolare).
type PolicyYAMLProvider interface {
	YAMLDocuments() []string
}

// TestResultRecord raccoglie tutte le informazioni da persistere per un
// singolo intento testato.
type TestResultRecord struct {
	Intent      string
	YAML        []string // uno o più documenti YAML (split su '---')
	TestScript  string
	TestOutput  string
	RunErr      error // errore di tester.RunTestScript, se presente
	Outcome     TestOutcome
	RolledBack  bool
	RollbackErr error
	Timestamp   time.Time
}

// LogTestResult scrive il record nel file appropriato (passed.txt, failed.txt,
// skipped.txt) dentro resultsDir, creando la cartella se non esiste.
// Va chiamata subito dopo aver eseguito il test script ed eventualmente il
// rollback, così il record è completo.
func LogTestResult(rec TestResultRecord) error {
	resultLogMu.Lock()
	defer resultLogMu.Unlock()

	if err := os.MkdirAll(resultsDir, 0o755); err != nil {
		return fmt.Errorf("creating results dir: %w", err)
	}

	var fname string
	switch rec.Outcome {
	case OutcomePassed:
		fname = passedFile
	case OutcomeFailed:
		fname = failedFile
	case OutcomeSkipped:
		fname = skippedFile
	default:
		fname = failedFile
	}

	path := filepath.Join(resultsDir, fname)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("opening %s: %w", path, err)
	}
	defer f.Close()

	entry := formatRecord(rec)
	if _, err := f.WriteString(entry); err != nil {
		return fmt.Errorf("writing to %s: %w", path, err)
	}

	return nil
}

// formatRecord produce il blocco di testo leggibile per un singolo risultato.
// Il formato è volutamente verboso e human-readable (non JSON), così come
// richiesto: pensato per essere letto/incollato direttamente, ad es. nel
// report di tesi, senza bisogno di un parser.
func formatRecord(rec TestResultRecord) string {
	var b strings.Builder

	sep := strings.Repeat("=", 70)
	b.WriteString(sep + "\n")
	b.WriteString(fmt.Sprintf("TIMESTAMP: %s\n", rec.Timestamp.Format(time.RFC3339)))
	b.WriteString(fmt.Sprintf("OUTCOME:   %s\n", outcomeLabel(rec.Outcome)))
	b.WriteString(sep + "\n\n")

	b.WriteString("--- INTENT ---\n")
	b.WriteString(strings.TrimSpace(rec.Intent) + "\n\n")

	b.WriteString("--- GENERATED YAML ---\n")
	if len(rec.YAML) == 0 {
		b.WriteString("(empty)\n\n")
	} else {
		for i, doc := range rec.YAML {
			if len(rec.YAML) > 1 {
				b.WriteString(fmt.Sprintf("[document %d/%d]\n", i+1, len(rec.YAML)))
			}
			b.WriteString(strings.TrimSpace(doc) + "\n")
			if i < len(rec.YAML)-1 {
				b.WriteString("---\n")
			}
		}
		b.WriteString("\n")
	}

	b.WriteString("--- TEST SCRIPT ---\n")
	if strings.TrimSpace(rec.TestScript) == "" {
		b.WriteString("(no test script)\n\n")
	} else {
		b.WriteString(strings.TrimSpace(rec.TestScript) + "\n\n")
	}

	// L'output del comando di test va sempre incluso per i FAIL (richiesto
	// esplicitamente), ma lo includiamo anche per PASS/SKIP per completezza
	// e per poter verificare a posteriori eventuali falsi positivi (come il
	// caso "Secure the cache" discusso in precedenza).
	b.WriteString("--- TEST OUTPUT ---\n")
	if strings.TrimSpace(rec.TestOutput) == "" {
		b.WriteString("(empty output)\n")
	} else {
		b.WriteString(strings.TrimSpace(rec.TestOutput) + "\n")
	}
	if rec.RunErr != nil {
		b.WriteString(fmt.Sprintf("RUN ERROR: %v\n", rec.RunErr))
	}
	b.WriteString("\n")

	if rec.Outcome == OutcomeFailed {
		b.WriteString("--- ROLLBACK ---\n")
		if rec.RolledBack {
			if rec.RollbackErr != nil {
				b.WriteString(fmt.Sprintf("Rollback attempted but FAILED: %v\n", rec.RollbackErr))
			} else {
				b.WriteString("Rollback completed successfully.\n")
			}
		} else {
			b.WriteString("No rollback performed.\n")
		}
		b.WriteString("\n")
	}

	return b.String()
}

func outcomeLabel(o TestOutcome) string {
	switch o {
	case OutcomePassed:
		return "PASS"
	case OutcomeFailed:
		return "FAIL"
	case OutcomeSkipped:
		return "SKIP"
	default:
		return "UNKNOWN"
	}
}

// splitYAMLDocuments spezza una stringa YAML multi-documento (separata da
// '---' su riga propria) in singoli documenti, per una resa più leggibile
// nel file di log.
func splitYAMLDocuments(yamlStr string) []string {
	if strings.TrimSpace(yamlStr) == "" {
		return nil
	}
	parts := strings.Split(yamlStr, "\n---")
	var docs []string
	for _, p := range parts {
		p = strings.TrimPrefix(strings.TrimSpace(p), "---")
		p = strings.TrimSpace(p)
		if p != "" {
			docs = append(docs, p)
		}
	}
	return docs
}
