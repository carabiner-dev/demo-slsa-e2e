// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/carabiner-dev/attestation"
	"github.com/carabiner-dev/collector/predicate/generic"
	"github.com/carabiner-dev/collector/statement/intoto"
	"github.com/carabiner-dev/hasher"
	"github.com/fatih/color"
	// Here we force the import of hashicorp/go-getter v1.7.9 which pulls
	// in CVE-2025-8959 and in the transitives CVE-2020-8912 and CVE-2020-8911.
	// Since we are only including the module, it does not affect the project,
	// but it should pop up in the scanners.
	//
	// ... perfect for VEXing :)
	//
	_ "github.com/hashicorp/go-getter"
	"github.com/spf13/cobra"
)

// Our custom predicate schema: "is it Friday?"
const FridayPredicateType = "https://carabiner.dev/built-on-friday/v1"

type FridayPredicate struct {
	BuiltOnFriday bool      `json:"builtOnFriday"`
	BuildTime     time.Time `json:"buildTime"`
	Notes         string    `json:"notes,omitempty"`
}

type fridayOptions struct {
	SubjectPath []string
	OutPath     string
	Time        string
	Predicate   string
	Notes       string
}

var opts = &fridayOptions{}

func (o *fridayOptions) Validate() error {
	if len(o.SubjectPath) == 0 {
		return fmt.Errorf("no subject files specified")
	}
	return nil
}

func main() {
	root := &cobra.Command{
		Use:   "fritoto [flags] file [file...]",
		Short: "🔏🍟 fritoto — in-toto attestor that asks the only question that matters: was it built on Friday?",
		Long:  banner(),
		RunE:  runGenerate,
		PreRun: func(_ *cobra.Command, args []string) {
			opts.SubjectPath = append(opts.SubjectPath, args...)
		},
	}

	root.PersistentFlags().StringSliceVarP(&opts.SubjectPath, "subject", "s", []string{}, "Paths to subject files to attest (required)")
	root.PersistentFlags().StringVarP(&opts.OutPath, "out", "o", "", "Output file for attestation (default: stdout)")
	root.PersistentFlags().StringVar(&opts.Time, "time", time.Now().Local().Format(time.RFC3339), "Build time to attest")
	root.PersistentFlags().StringVar(&opts.Notes, "notes", "", "Optional note to include in the predicate")

	_ = root.MarkFlagRequired("subject") //nolint:errcheck

	if err := root.Execute(); err != nil {
		color.New(color.FgHiYellow).Fprintf(os.Stderr, "%s error: %v\n", color.RedString("✖"), err) //nolint:errcheck,gosec
		os.Exit(1)
	}
}

// IsItFriday is the core logic of the app. It computes if the date IS A FRIDAY!
func IsItFriday(buildTime time.Time) bool {
	return buildTime.Weekday() == time.Friday
}

func runGenerate(cmd *cobra.Command, args []string) error {
	if err := opts.Validate(); err != nil {
		return err
	}
	fmt.Println()
	color.New(color.FgHiWhite, color.Bold).Println("  ✨ Generating in-toto attestation") //nolint:errcheck,gosec
	fmt.Println()

	fmt.Print("  • ")
	color.HiCyan("🧮 Hashing subject…")

	hashes, err := hasher.New().HashFiles(opts.SubjectPath)
	if err != nil {
		return fmt.Errorf("hashing files: %w", err)
	}

	// Determine time & Friday-ness
	var buildTime time.Time
	if opts.Time == "" {
		buildTime = time.Now()
	} else {
		t, err := time.Parse(time.RFC3339, opts.Time)
		if err != nil {
			return fmt.Errorf("invalid --time: %w", err)
		}
		buildTime = t
	}
	isFriday := buildTime.Weekday() == time.Friday

	fmt.Print("  • ")
	color.HiCyan("📅 Build time: %s (%s)", buildTime.Format(time.RFC3339), buildTime.Location())

	if isFriday {
		fmt.Print("  • ")
		color.New(color.FgGreen, color.Bold).Println("🎉 T.G.I.F.! It *is* a Friday build. No need to deploy, woohoo!") //nolint:errcheck,gosec
	} else {
		fmt.Print("  • ")
		color.New(color.FgBlue, color.Bold).Println("🧊 Not Friday. Stay cool and ship.") //nolint:errcheck,gosec
	}

	// Create the statement
	var stmt attestation.Statement = intoto.NewStatement(
		intoto.WithPredicate(
			&generic.Predicate{
				Type: FridayPredicateType,
				Parsed: &FridayPredicate{
					BuiltOnFriday: isFriday,
					BuildTime:     buildTime,
					Notes:         opts.Notes,
				},
			},
		),
		intoto.WithSubject(hashes.ToResourceDescriptors()...),
	)

	out := os.Stdout
	if opts.OutPath != "" {
		f, err := os.Create(opts.OutPath)
		if err != nil {
			return err
		}
		defer f.Close() //nolint:errcheck
		out = f
	}

	fmt.Print("  • ")
	color.HiCyan("🧾 Writing attestation…")
	fmt.Println()

	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	if err := enc.Encode(stmt); err != nil {
		return err
	}

	if opts.OutPath != "" {
		color.HiWhite("✅ Done! Attestation saved to %s", opts.OutPath)
	} else {
		fmt.Println()
		color.HiWhite("✅ Done!")
	}

	color.New(color.FgHiCyan, color.Bold).Print("🔐 Pro-tip!") //nolint:errcheck,gosec
	color.HiCyan(" Sign your JSON with bnd for extra ✨ vibes.")
	fmt.Println()

	return nil
}

func banner() string {
	return color.New(color.FgHiMagenta, color.Bold).Sprint(`
     _               
   _|_._o_|_ __|_ _  
    | | | |_(_)|_(_) 

`) + color.New(color.FgWhite, color.Bold).Sprintf("   🔏🍟 fritoto — the *Friday-or-not* attestationator")
}
