#include <cerrno>
#include <cstring>
#include <err.h>
#include <pwd.h>
#include <spawn.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <iostream>

/* Work around nix's config.h */
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION
#include <eval.hh>
#include <eval-inline.hh>
#include <util.hh>

using boost::format;
using nix::EvalError;
using nix::SysError;
using nix::Error;
using nix::Value;
using nix::Path;

static const char * decrypt_sh =  NIXEXEC_LIBEXEC_DIR "/decrypt.sh";

static Path get_default_cache_dir() {
  auto home = ::getenv("HOME");
  if (!home) {
    errno = 0;
    auto pwd = getpwuid(getuid());
    if (pwd)
      home = pwd->pw_dir;
    else if (errno)
      throw SysError("getting password file entry for current user");
    else if (!home)
      throw SysError("no home for current user");
  }

  return Path{home} + "/.gnupg/nix-secrets-cache";
}

extern "C" void decrypt( nix::EvalState & state
                        , const nix::Pos & pos
                        , Value ** args
                        , Value & v
                        ) {
  auto cache_sym = state.symbols.create("cache-dir");
  auto file_sym = state.symbols.create("file");
  auto context = nix::PathSet{};

  state.forceAttrs(*args[0]);

  auto cache_iter = args[0]->attrs->find(cache_sym);
  auto cache_dir = cache_iter == args[0]->attrs->end() ?
    get_default_cache_dir() :
    state.coerceToPath(*cache_iter->pos, *cache_iter->value, context);
  if (!context.empty())
    throw EvalError(format(
      "the cache directory is not allowed to refer to a store path (such as `%1%'), at %2%"
    ) % *context.begin() % *cache_iter->pos);

  auto file_iter = args[0]->attrs->find(file_sym);
  if (file_iter == args[0]->attrs->end())
    throw EvalError(format("required attribute `file' missing, at %1%") % pos);
  auto file = state.coerceToPath(*file_iter->pos, *file_iter->value, context);

  auto sha1 = nix::printHash(nix::hashFile(nix::HashType::htSHA1, file));
  std::cerr << "decrypting `" << file << "' to `" << cache_dir << "/' ..." << std::endl;

  const char * const argv[] = { decrypt_sh
                              , file.c_str()
                              , cache_dir.c_str()
                              , nullptr
                              };
  int status;
  pid_t child;

  status = posix_spawnp(&child, decrypt_sh, nullptr, nullptr,
      const_cast<char * const *>(argv), environ);

  errno = status;
  if (status)
    throw SysError("posix_spawnp");

  errno = 0;
  while (waitpid(child, &status, 0) == -1 && errno == EINTR);
  if (errno && errno != EINTR)
    throw SysError("waiting for decrypt");
  if (WIFEXITED(status)) {
    auto code = WEXITSTATUS(status);
    if (code)
      throw Error(format("decrypt exited with non-zero exit code %1%") % code);
  } else if (WIFSIGNALED(status))
    throw Error(format("decrypt killed by signal %1%") % strsignal(WTERMSIG(status)));
  else
    throw Error("decrypt died in unknown manner");

  std::string secret = cache_dir + "/" + sha1;
  nix::mkPath(v, secret.c_str());
}
