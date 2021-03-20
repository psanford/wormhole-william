package cmd

import (
	"context"
	"os"
	"strings"
	"time"

	"github.com/psanford/wormhole-william/internal/crypto"
	"github.com/psanford/wormhole-william/rendezvous"
	"github.com/psanford/wormhole-william/wordlist"
	"github.com/psanford/wormhole-william/wormhole"
	"github.com/spf13/cobra"
)

func completionCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "shell-completion [bash|zsh|fish|powershell]",
		Short: "Generate shell completion script",
		Long: `To load completions:

Bash:

  $ source <(wormhole-william shell-completion bash)

  # To configure your bash shell to load completions for each session add to your bashrc

# ~/.bashrc or ~/.profile
if which wormhole-william &>/dev/null ; then
  . <(wormhole-william shell-completion bash)
fi

Zsh:

  # If shell completion is not already enabled in your environment,
  # you will need to enable it.  You can execute the following once:

  $ echo "autoload -U compinit; compinit" >> ~/.zshrc

  # To load completions for each session, execute once:
  $ wormhole-william shell-completion zsh > "${fpath[1]}/_wormhole-william"

  # You will need to start a new shell for this setup to take effect.

fish:

  $ wormhole-william shell-completion fish | source

  # To load completions for each session, execute once:
  $ wormhole-william shell-completion fish > ~/.config/fish/completions/wormhole-william.fish

PowerShell:

  PS> wormhole-william shell-completion powershell | Out-String | Invoke-Expression

  # To load completions for every new session, run:
  PS> wormhole-william shell-completion powershell > wormhole-william.ps1
  # and source this file from your PowerShell profile.
`,
		DisableFlagsInUseLine: true,
		ValidArgs:             []string{"bash", "zsh", "fish", "powershell"},
		Args:                  cobra.ExactValidArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			switch args[0] {
			case "bash":
				cmd.Root().GenBashCompletion(os.Stdout)
			case "zsh":
				cmd.Root().GenZshCompletion(os.Stdout)
			case "fish":
				cmd.Root().GenFishCompletion(os.Stdout, true)
			case "powershell":
				cmd.Root().GenPowerShellCompletionWithDesc(os.Stdout)
			}
		},
	}

	return cmd
}

func recvCodeCompletion(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	flags := cobra.ShellCompDirectiveNoFileComp | cobra.ShellCompDirectiveNoSpace
	parts := strings.Split(toComplete, "-")
	if len(parts) < 2 {
		nameplates, err := activeNameplates()
		if err != nil {
			return nil, flags
		}
		if len(parts) == 0 {
			return nameplates, flags
		}

		var candidates []string
		for _, nameplate := range nameplates {
			if strings.HasPrefix(nameplate, parts[0]) {
				candidates = append(candidates, nameplate+"-")
			}
		}

		return candidates, flags
	}

	currentCompletion := parts[len(parts)-1]
	prefix := parts[:len(parts)-1]

	// even odd is based on just the number of words so slice off the mailbox
	parts = parts[1:]
	even := len(parts)%2 == 0

	var candidates []string
	for _, pair := range wordlist.RawWords {
		var candidateWord string
		if even {
			candidateWord = pair.Even
		} else {
			candidateWord = pair.Odd
		}
		if strings.HasPrefix(candidateWord, currentCompletion) {
			guessParts := append(prefix, candidateWord)
			candidates = append(candidates, strings.Join(guessParts, "-"))
		}
	}

	return candidates, flags
}

func activeNameplates() ([]string, error) {
	url := wormhole.DefaultRendezvousURL
	sideID := crypto.RandSideID()
	appID := wormhole.WormholeCLIAppID

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()

	client := rendezvous.NewClient(url, sideID, appID)

	mood := rendezvous.Happy
	defer client.Close(ctx, mood)

	_, err := client.Connect(ctx)
	if err != nil {
		return nil, err
	}

	return client.ListNameplates(ctx)
}
