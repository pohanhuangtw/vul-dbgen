//go:build appsonly

package main

import (
	"encoding/json"
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/vul-dbgen/updater"
	"github.com/vul-dbgen/updater/fetchers/apps"
)

func main() {
	appFetchers := map[string]updater.AppFetcher{
		"openssl": &apps.AppFetcher{},
	}
	for name, f := range appFetchers {
		response, err := f.FetchUpdate()
		if err != nil {
			log.WithFields(log.Fields{"name": name, "error": err}).Error("App CVE update FAIL")
		} else {
			log.WithFields(log.Fields{"name": name, "count": len(response.Vulnerabilities)}).Info("App CVE update SUCCESS")

			// Write apps.tb as JSONL (one record per line)
			fout, ferr := os.Create("apps.tb")
			if ferr != nil {
				log.WithFields(log.Fields{"error": ferr}).Error("Failed to create apps.tb")
				continue
			}
			for _, mv := range response.Vulnerabilities {
				if mv.VulName == "GO-2025-3849" {
					log.WithFields(log.Fields{"mv": mv}).Info("mv")
				}
			}
			for _, mv := range response.Vulnerabilities {
				b, jerr := json.Marshal(mv)
				if jerr != nil {
					log.WithFields(log.Fields{"error": jerr}).Warn("Failed to marshal AppModuleVul")
					continue
				}
				if _, werr := fout.Write(append(b, '\n')); werr != nil {
					log.WithFields(log.Fields{"error": werr}).Warn("Failed to write record to apps.tb")
				}
			}
			fout.Close()
			log.WithFields(log.Fields{"file": "apps.tb"}).Info("apps.tb generated")
		}
	}
}
