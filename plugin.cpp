#include <nix/expr/eval.hh>
#include <nix/expr/primops.hh>
#include <nix/store/content-address.hh>
#include <nix/store/store-api.hh>
#include <nix/util/environment-variables.hh>
#include <nix/util/file-system.hh>
#include <nix/util/hash.hh>
#include <nix/util/logging.hh>
#include <nix/util/processes.hh>
#include <nix/util/serialise.hh>
#include <nix/util/users.hh>

#include <filesystem>

#ifndef AGE_PATH
#define AGE_PATH "age"
#endif

using namespace nix;

struct IdentityDiscovery {
    std::vector<Path> candidates;
    std::vector<Path> usable;
};

static IdentityDiscovery discoverIdentities()
{
    IdentityDiscovery result;

    if (auto env = getEnv("AGE_IDENTITY_FILE")) {
        result.candidates.push_back(*env);
    } else {
        try {
            auto home = std::filesystem::path(getHome());
            result.candidates.push_back((home / ".ssh" / "id_ed25519").string());
            result.candidates.push_back((home / ".ssh" / "id_rsa").string());
        } catch (...) {
        }
    }

    for (auto & p : result.candidates) {
        if (pathAccessible(p))
            result.usable.push_back(p);
    }

    return result;
}

static std::string decryptWithAge(const Path & encryptedPath, const std::vector<Path> & identities)
{
    Strings args = {"--decrypt"};
    for (auto & id : identities) {
        args.push_back("-i");
        args.push_back(id);
    }
    args.push_back(encryptedPath);
    return runProgram(AGE_PATH, false, args);
}

static std::string stripAgeSuffix(std::string_view name)
{
    if (name.ends_with(".age"))
        return std::string(name.substr(0, name.size() - 4));
    return std::string(name);
}

static std::string describeCandidate(const Path & p)
{
    try {
        if (!std::filesystem::exists(p))
            return p + " (not found)";
        if (!pathAccessible(p))
            return p + " (not readable)";
        return p + " (found)";
    } catch (...) {
        return p + " (inaccessible)";
    }
}

// Core logic shared by importAge and readAge.
// Decrypts if necessary and ensures the result is in the store.
// Returns the store path of the decrypted content.
static StorePath resolveAge(
    EvalState & state,
    const PosIdx pos,
    std::string_view who,
    const SourcePath & encryptedFile,
    std::optional<Hash> expectedHash)
{
    auto baseName = encryptedFile.path.baseName();
    auto name = stripAgeSuffix(baseName.value_or("source"));

    if (expectedHash) {
        if (expectedHash->algo != HashAlgorithm::SHA256)
            state.error<EvalError>("%s only supports SHA-256 hashes", who).atPos(pos).debugThrow();

        auto expectedPath = state.store->makeFixedOutputPath(
            name,
            FixedOutputInfo{
                .method = FileIngestionMethod::Flat,
                .hash = *expectedHash,
                .references = {},
            });

        // ensurePath also tries substituters, so a store path populated
        // on another machine and pushed to a cache can be used here
        // without any local decryption.
        try {
            state.store->ensurePath(expectedPath);
            return expectedPath;
        } catch (Error &) {
            // Fall through to decryption.
        }
    } else if (state.settings.pureEval) {
        state
            .error<EvalError>(
                "%s requires 'hash' in pure evaluation mode. "
                "Run with '--impure' for first-time decryption, "
                "then add the printed hash to your expression.",
                who)
            .atPos(pos)
            .debugThrow();
    }

    auto discovery = discoverIdentities();

    if (discovery.usable.empty()) {
        std::string detail;
        if (discovery.candidates.empty()) {
            detail = "no candidate paths (could not determine home directory)";
        } else {
            detail = "checked: ";
            for (size_t i = 0; i < discovery.candidates.size(); ++i) {
                if (i > 0)
                    detail += ", ";
                detail += describeCandidate(discovery.candidates[i]);
            }
        }

        auto msg = fmt(
            "%s: no usable identity found. %s. "
            "Set AGE_IDENTITY_FILE or ensure a key exists at a default path.",
            who,
            detail);

        if (expectedHash)
            msg += " The hash-locked store path is not present and no identity was found to decrypt."
                   " You may need to run an initial impure evaluation on a machine with the identity,"
                   " or populate the store path via substitution.";

        state.error<EvalError>("%s", msg).atPos(pos).debugThrow();
    }

    auto encryptedPath = encryptedFile.path.abs();

    if (!std::filesystem::exists(encryptedPath))
        state
            .error<EvalError>(
                "%s: file '%s' does not exist. "
                "If you are using flakes, ensure the file has been added to git.",
                who,
                encryptedFile)
            .atPos(pos)
            .debugThrow();

    std::string content;
    try {
        content = decryptWithAge(encryptedPath, discovery.usable);
    } catch (ExecError & e) {
        state
            .error<EvalError>(
                "%s: age failed to decrypt '%s': %s",
                who,
                encryptedFile,
                e.what())
            .atPos(pos)
            .debugThrow();
    }

    auto actualHash = hashString(HashAlgorithm::SHA256, content);

    if (expectedHash && actualHash != *expectedHash)
        state
            .error<EvalError>(
                "%s: hash mismatch for '%s'.\n"
                "  specified: %s\n"
                "  got:       %s\n"
                "(did you update the encrypted file without updating the hash?)",
                who,
                encryptedFile,
                expectedHash->to_string(HashFormat::SRI, true),
                actualHash.to_string(HashFormat::SRI, true))
            .atPos(pos)
            .debugThrow();

    StringSource source(content);
    auto storePath = state.store->addToStoreFromDump(
        source,
        name,
        FileSerialisationMethod::Flat,
        ContentAddressMethod{ContentAddressMethod::Raw::Flat},
        HashAlgorithm::SHA256,
        {},
        state.repair);

    if (!expectedHash)
        warn(
            "%s: hash for '%s' is:\n  hash = \"%s\";",
            who,
            encryptedFile,
            actualHash.to_string(HashFormat::SRI, true));

    return storePath;
}

struct AgeAttrs {
    SourcePath file;
    std::optional<Hash> hash;
};

static AgeAttrs parseAgeAttrs(EvalState & state, const PosIdx pos, Value ** args, std::string_view who)
{
    state.forceAttrs(*args[0], pos, fmt("while evaluating the argument passed to '%s'", who));

    std::optional<SourcePath> file;
    std::optional<Hash> hash;

    for (auto & attr : *args[0]->attrs()) {
        auto attrName = state.symbols[attr.name];
        if (attrName == "file") {
            NixStringContext ctx;
            file = state.coerceToPath(
                attr.pos, *attr.value, ctx, fmt("while evaluating the 'file' attribute passed to '%s'", who));
        } else if (attrName == "hash") {
            auto s = state.forceStringNoCtx(
                *attr.value, attr.pos, fmt("while evaluating the 'hash' attribute passed to '%s'", who));
            if (!s.empty())
                hash = newHashAllowEmpty(s, HashAlgorithm::SHA256);
        } else {
            state.error<EvalError>("unsupported attribute '%s' in '%s'", attrName, who)
                .atPos(attr.pos)
                .debugThrow();
        }
    }

    if (!file)
        state.error<EvalError>("'file' attribute is required in '%s'", who).atPos(pos).debugThrow();

    return {std::move(*file), std::move(hash)};
}

static void prim_importAge(EvalState & state, const PosIdx pos, Value ** args, Value & v)
{
    auto [file, hash] = parseAgeAttrs(state, pos, args, "builtins.importAge");
    auto storePath = resolveAge(state, pos, "builtins.importAge", file, hash);
    state.allowPath(storePath);

    auto sourcePath = state.rootPath(CanonPath(state.store->printStorePath(storePath)));
    try {
        state.evalFile(sourcePath, v);
    } catch (Error & e) {
        e.addTrace(state.positions[pos], "while evaluating the decrypted content from 'builtins.importAge'");
        throw;
    }
}

static void prim_readAge(EvalState & state, const PosIdx pos, Value ** args, Value & v)
{
    auto [file, hash] = parseAgeAttrs(state, pos, args, "builtins.readAge");
    auto storePath = resolveAge(state, pos, "builtins.readAge", file, hash);
    state.allowPath(storePath);

    auto content = nix::readFile(state.store->printStorePath(storePath));
    if (content.find('\0') != std::string::npos)
        state
            .error<EvalError>(
                "builtins.readAge: the decrypted contents of '%s' cannot be represented as a Nix string", file)
            .atPos(pos)
            .debugThrow();
    v.mkString(content); // nix 2.31
    // v.mkString(content, state.mem); // this works in master
}

static RegisterPrimOp primop_importAge({
    .name = "importAge",
    .args = {"attrs"},
    .doc = R"(
      Decrypt an age-encrypted `.nix` file and return its evaluated contents.

      *attrs* is an attribute set with the following attributes:

      - `file` (path, required): Path to the age-encrypted file.
      - `hash` (string, optional): SRI hash (SHA-256) of the decrypted content.

      When `hash` is provided and the corresponding store path exists,
      the result is returned from cache with no decryption or identity needed,
      enabling pure evaluation. Without `hash`, impure mode is required.
    )",
    .fun = prim_importAge,
});

static RegisterPrimOp primop_readAge({
    .name = "readAge",
    .args = {"attrs"},
    .doc = R"(
      Decrypt an age-encrypted file and return its contents as a string.

      *attrs* is an attribute set with the following attributes:

      - `file` (path, required): Path to the age-encrypted file.
      - `hash` (string, optional): SRI hash (SHA-256) of the decrypted content.

      When `hash` is provided and the corresponding store path exists,
      the result is returned from cache with no decryption or identity needed,
      enabling pure evaluation. Without `hash`, impure mode is required.
    )",
    .fun = prim_readAge,
});
