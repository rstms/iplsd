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
	"fmt"
	"log"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string

var rootCmd = &cobra.Command{
	Version: "0.0.1",
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

		DaemonizeDisabled = viper.GetBool("debug")
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
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "/etc/iplsd/config.yaml", "config file")
	OptionString("logfile", "l", "/var/log/iplsd", "log filename")
	OptionSwitch("debug", "", "run in foreground")
	OptionSwitch("verbose", "v", "increase verbosity")
	OptionString("interval-seconds", "", "600", "timeout check interval in seconds (default: 10 minutes)")
	OptionString("timeout-seconds", "", "86400", "IP presence timeout in seconds (default: 24 hours)")
	OptionString("monitored-file", "m", "", "log file to monitor")
	OptionString("address-file", "w", "/etc/iplsd/watchlist", "IP whitelist/blacklist table file")
	OptionString("timeout-dir", "d", "/etc/iplsd/timeout", "IP timeout file directory")
	OptionString("regex", "r", `((?:\d{1,3}\.){3}\d{1,3})`, "regex patterns")
}
func initConfig() {
	if cfgFile != "" {
		if !IsFile(cfgFile) {
			cobra.CheckErr(fmt.Errorf("config file '%s' not found\n", cfgFile))
		}
		viper.SetConfigFile(cfgFile)
	} else {
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)
		viper.AddConfigPath(home)
		viper.SetConfigType("yaml")
		viper.SetConfigName(".iplsd")
	}
	viper.SetEnvPrefix(rootCmd.Name())
	viper.AutomaticEnv()
	err := viper.ReadInConfig()
	cobra.CheckErr(err)
	OpenLog()
	if viper.GetBool("verbose") {
		log.Println("Using config file:", viper.ConfigFileUsed())
	}
}
