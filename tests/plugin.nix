{ pkgs, mini-agenix }:

pkgs.testers.runNixOSTest {
  name = "mini-agenix-plugin";

  nodes.machine =
    { pkgs, ... }:
    {
      virtualisation.writableStore = true;
      environment.systemPackages = [
        pkgs.age
        pkgs.nix
      ];
      nix.settings.experimental-features = [ "nix-command" ];
    };

  testScript =
    let
      plugin = "${mini-agenix}/lib/libmini_agenix.so";
      nix = builtins.concatStringsSep " " [
        "nix eval"
        "--option plugin-files ${plugin}"
        "--option allow-unsafe-native-code-during-evaluation true"
        "--extra-experimental-features nix-command"
      ];
    in
    ''
      DIR = "/tmp/test"
      KEY = f"{DIR}/key.txt"
      NIX = "${nix}"

      def nix_eval(expr, *, impure=False, pure=False, raw=False, env="", expect_fail=False):
          """Write a Nix expression to a file and evaluate it."""
          machine.succeed(f"cat > {DIR}/eval.nix <<'NIXEOF'\n{expr}\nNIXEOF")
          flags = ""
          if impure:
              flags += " --impure"
          if pure:
              flags += " --option pure-eval true"
          if raw:
              flags += " --raw"
          prefix = f"{env} " if env else ""
          cmd = f"cd {DIR} && {prefix}{NIX}{flags} --file {DIR}/eval.nix"
          if expect_fail:
              return machine.fail(f"{cmd} 2>&1")
          return machine.succeed(f"{cmd} 2>/dev/null")

      def capture_hash(expr, env=""):
          """Evaluate an expression impurely and extract the hash from stderr."""
          machine.succeed(f"cat > {DIR}/eval.nix <<'NIXEOF'\n{expr}\nNIXEOF")
          prefix = f"{env} " if env else ""
          return machine.succeed(
              f"cd {DIR} && ({prefix}{NIX} --impure --file {DIR}/eval.nix "
              ">/dev/null 2>/tmp/test/stderr.log || true) && "
              "grep -oP 'sha256-[A-Za-z0-9+/=]+' /tmp/test/stderr.log"
          ).strip()

      machine.wait_for_unit("default.target")

      # ── fixture setup ──

      machine.succeed(f"mkdir -p {DIR}")
      machine.succeed(f"age-keygen -o {KEY} 2>{DIR}/rcpt.txt")
      machine.succeed(
          f"RCPT=$(grep -i 'public key' {DIR}/rcpt.txt | awk '{{print $NF}}') && "
          f"echo -n 'hello from age' | age -r $RCPT -o {DIR}/plain.txt.age"
      )
      machine.succeed(
          f"RCPT=$(grep -i 'public key' {DIR}/rcpt.txt | awk '{{print $NF}}') && "
          f"echo '{{ x = 42; }}' | age -r $RCPT -o {DIR}/expr.nix.age"
      )
      machine.succeed(
          f"RCPT=$(grep -i 'public key' {DIR}/rcpt.txt | awk '{{print $NF}}') && "
          f"printf 'has\\x00null' | age -r $RCPT -o {DIR}/null.bin.age"
      )

      env = f"AGE_IDENTITY_FILE={KEY}"

      # ── readAge impure ──

      result = nix_eval(
          f"builtins.readAge {{ file = {DIR}/plain.txt.age; }}",
          impure=True, raw=True, env=env,
      )
      assert result == "hello from age", f"readAge impure: {result!r}"

      # ── capture hash for locked-mode tests ──

      hash = capture_hash(
          f"builtins.readAge {{ file = {DIR}/plain.txt.age; }}",
          env=env,
      )
      assert hash.startswith("sha256-"), f"bad hash: {hash!r}"
      machine.log(f"readAge hash: {hash}")

      # ── readAge locked (correct hash) ──

      result = nix_eval(
          f'builtins.readAge {{ file = {DIR}/plain.txt.age; hash = "{hash}"; }}',
          raw=True, env=env,
      )
      assert result == "hello from age", f"readAge locked: {result!r}"

      # ── readAge wrong hash → error ──

      nix_eval(
          f'builtins.readAge {{ file = {DIR}/plain.txt.age; hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="; }}',
          impure=True, raw=True, env=env, expect_fail=True,
      )

      # ── readAge null bytes → error ──

      nix_eval(
          f"builtins.readAge {{ file = {DIR}/null.bin.age; }}",
          impure=True, raw=True, env=env, expect_fail=True,
      )

      # ── importAge impure ──

      result = nix_eval(
          f"(builtins.importAge {{ file = {DIR}/expr.nix.age; }}).x",
          impure=True, env=env,
      ).strip()
      assert result == "42", f"importAge impure: {result!r}"

      # ── importAge locked (correct hash) ──

      import_hash = capture_hash(
          f"(builtins.importAge {{ file = {DIR}/expr.nix.age; }}).x",
          env=env,
      )
      result = nix_eval(
          f'(builtins.importAge {{ file = {DIR}/expr.nix.age; hash = "{import_hash}"; }}).x',
          env=env,
      ).strip()
      assert result == "42", f"importAge locked: {result!r}"

      # ── pure eval without hash → error ──

      nix_eval(
          f"builtins.readAge {{ file = {DIR}/plain.txt.age; }}",
          pure=True, raw=True, env=env, expect_fail=True,
      )

      # ── missing identity → clear error message ──

      output = nix_eval(
          f"builtins.readAge {{ file = {DIR}/plain.txt.age; }}",
          impure=True, raw=True, env="AGE_IDENTITY_FILE=/nonexistent/key",
          expect_fail=True,
      )
      assert "no usable identity" in output, f"missing identity: {output!r}"

      # ── SSH key discovery (~/.ssh/id_ed25519) ──

      machine.succeed(
          f"mkdir -p /root/.ssh && "
          f"cp {KEY} /root/.ssh/id_ed25519 && "
          "chmod 600 /root/.ssh/id_ed25519"
      )
      result = nix_eval(
          f"builtins.readAge {{ file = {DIR}/plain.txt.age; }}",
          impure=True, raw=True,  # no env — must discover from ~/.ssh
      )
      assert result == "hello from age", f"SSH discovery: {result!r}"
      machine.succeed("rm /root/.ssh/id_ed25519")

      # ── locked mode without identity (store path already cached) ──

      result = nix_eval(
          f'builtins.readAge {{ file = {DIR}/plain.txt.age; hash = "{hash}"; }}',
          raw=True, env="AGE_IDENTITY_FILE=/nonexistent/key",
      )
      assert result == "hello from age", f"cached no-identity: {result!r}"

      machine.log("all mini-agenix tests passed")
    '';
}
