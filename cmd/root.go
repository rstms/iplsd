/*
Copyright © 2025 Matt Krueger <mkrueger@rstms.net>
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

 1. Redistributions of source code must retain the above copyright notice,
    this list of conditions and the following disclaimer.

 2. Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.

 3. Neither the name of the copyright holder nor the names of its contributors
    may be used to endorse or promote products derived from this software
    without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
*/
package cmd

import (
	"log"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var rootCmd = &cobra.Command{
	Version: "0.2.1",
	Use:     "iplsd",
	Short:   "IP log scan daemon",
	Long: `

iplsd pf-table log scanning daemon

Scan log files for regex patterns containing IP addresses.

Open LOG_FILE; For each line added:
  Match the line with REGEX

When a pattern match produces a new IP_ADDRESS:
  Append IP_ADDRESS to LIST_FILE if not already present
  Write the timeout time into TIMEOUT_DIR/IP_ADDRESS

Every TIMEOUT_INTERVAL: 
  Read IP_ADDRESS (filename) and timeout (content) from TIMEOUT_DIR/*
  If the timeout has expired:
    Remove IP_ADDRESS from WATCHLIST_FILE
    Delete TIMEOUT_DIR/IP_ADDRESS

Use case: maintain IP address list table file for a pf rule

`,
	Run: func(cmd *cobra.Command, args []string) {

		DaemonizeDisabled = viper.GetBool("foreground")
		Daemonize(func() {
			scanner, err := NewScanner(
				viper.GetString("address_file"),
				viper.GetString("timeout_dir"),
				viper.GetStringSlice("regex"),
			)
			if err != nil {
				log.Fatal(err)
			}
			if viper.GetBool("verbose") {
				log.Println(FormatJSON(scanner))
			}
			err = scanner.Scan(viper.GetString("monitored_file"))
			if err != nil {
				log.Fatal(err)
			}
		}, viper.GetString("logfile"))

	},
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(InitConfig)
	OptionString("config", "c", "", "config file")
	OptionString("logfile", "l", "", "log filename (default: stderr)")
	OptionSwitch("foreground", "", "run in foreground")
	OptionSwitch("verbose", "v", "increase verbosity")
	OptionString("interval-seconds", "", "600", "timeout check interval in seconds (default: 10 minutes)")
	OptionString("timeout-seconds", "", "86400", "IP presence timeout in seconds (default: 24 hours)")
	OptionString("monitored-file", "m", "", "log file to monitor")
	OptionString("address-file", "w", "/etc/iplsd/watchlist", "IP whitelist/blacklist table file")
	OptionString("timeout-dir", "d", "/etc/iplsd/ip", "IP timeout file directory")
	OptionString("regex", "r", `((?:\d{1,3}\.){3}\d{1,3})`, "regex patterns")
}
