#include <cerrno>
#include <cstring>
#include <err.h>
#include <pwd.h>
#include <spawn.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

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

static Path get_default_cache_dir() {
  auto home = ::getenv("HOME");
  if (!home) {
    errno = 0;
    auto pwd = getpwuid(getuid());
    if (pwd)
      home = pwd->pw_dir;
    else if (errno)
      throw SysError("getting password file entry for current user");
  }

  return home ? Path{home} + "/.cache/fetchgit" : "/var/lib/empty/.cache/fetchgit";
}

extern "C" void fetchgit( nix::EvalState & state
                        , const nix::Pos & pos
                        , Value ** args
                        , Value & v
                        ) {
  static auto default_cache_dir = get_default_cache_dir();

  auto cache_sym = state.symbols.create("cache-dir");
  auto url_sym = state.symbols.create("url");
  auto rev_sym = state.symbols.create("rev");
  auto submodules_sym = state.symbols.create("fetchSubmodules");

  state.forceAttrs(*args[0]);

  auto cache_iter = args[0]->attrs->find(cache_sym);
  auto context = nix::PathSet{};
  auto cache_dir = cache_iter == args[0]->attrs->end() ?
    default_cache_dir :
    state.coerceToPath(*cache_iter->pos, *cache_iter->value, context);
  if (!context.empty())
    throw EvalError(format(
      "the cache directory is not allowed to refer to a store path (such as `%1%'), at %2%"
    ) % *context.begin() % *cache_iter->pos);

  auto url_iter = args[0]->attrs->find(url_sym);
  if (url_iter == args[0]->attrs->end())
    throw EvalError(format("required attribute `url' missing, at %1%") % pos);
  auto url = state.coerceToString(*url_iter->pos, *url_iter->value, context, false, false);
  if (!context.empty())
    throw EvalError(format(
      "the url is not allowed to refer to a store path (such as `%1%'), at %2%"
    ) % *context.begin() % *url_iter->pos);

  auto rev_iter = args[0]->attrs->find(rev_sym);
  if (rev_iter == args[0]->attrs->end())
    throw EvalError(format("required attribute `rev' missing, at %1%") % pos);
  auto rev = state.forceStringNoCtx(*rev_iter->value, *rev_iter->pos);

  auto submodules_iter = args[0]->attrs->find(submodules_sym);
  auto do_submodules = submodules_iter == args[0]->attrs->end() ?
    true :
    state.forceBool(*submodules_iter->value);

  constexpr char fetchgit_path[] = NIXEXEC_LIBEXEC_DIR "/fetchgit.sh";
  const char * const argv[] = { fetchgit_path
                              , cache_dir.c_str()
                              , url.c_str()
                              , rev.c_str()
                              , do_submodules ? "true" : "false"
                              , nullptr
                              };
  int in[2];
  int status;
  short int flags = 0;
  pid_t child;
  posix_spawn_file_actions_t action;
  posix_spawnattr_t attr;

  pipe(in);
  posix_spawn_file_actions_init(&action);
  posix_spawnattr_init(&attr);
  posix_spawn_file_actions_adddup2(&action, in[1], 1);
  posix_spawn_file_actions_addclose(&action, in[0]);

#if defined(POSIX_SPAWN_USEVFORK)
  flags |= POSIX_SPAWN_USEVFORK;
#endif
  posix_spawnattr_setflags(&attr, flags);

  status = posix_spawnp(&child, fetchgit_path, &action, &attr,
      const_cast<char * const *>(argv), environ);
  close(in[1]);
  posix_spawn_file_actions_destroy(&action);
  posix_spawnattr_destroy(&attr);

  errno = status;
  if (status)
    throw SysError("posix_spawnp");

  auto path = nix::drainFD(in[0]);

  errno = 0;
  while (waitpid(child, &status, 0) == -1 && errno == EINTR);
  if (errno && errno != EINTR)
    throw SysError("waiting for fetchgit");
  if (WIFEXITED(status)) {
    auto code = WEXITSTATUS(status);
    if (code)
      throw Error(format("fetchgit exited with non-zero exit code %1%") % code);
  } else if (WIFSIGNALED(status))
    throw Error(format("fetchgit killed by signal %1%") % strsignal(WTERMSIG(status)));
  else
    throw Error("fetchgit died in unknown manner");

  nix::mkPath(v, path.c_str());
}
