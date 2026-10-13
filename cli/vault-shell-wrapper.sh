# Source from ~/.bashrc or ~/.zshrc to enable `vault env load` in the current shell.
#
#   eval "$(cat /path/to/noema-vault/cli/vault-shell-wrapper.sh)"
#
vault() {
    if [[ "$1" == "env" && "$2" == "load" ]]; then
        eval "$(command vault env load "$3")"
    else
        command vault "$@"
    fi
}
