"""
git branch -m master main
git fetch origin
git branch -u origin/master main
git remote set-head origin -a

find . -type f -path '*/.git/config' -print0 |
xargs -0 grep -l --null gitlab.com |
while IFS= read -r -d ''; do
    dir="$(dirname "$REPLY")"
    dir="$(dirname "$dir")"
    (   
        cd "$dir" &&
        pwd &&
        git branch -m master main &&
        git fetch origin &&
        git branch -u origin/main main &&
        git remote set-head origin -a
    )   
done
"""
import argparse
import logging
import os
import requests
from textwrap import dedent

log = logging.getLogger(__name__)


def rename_default_branch(gitlab, p, *, from_branch, to_branch, force):
    pid = p["id"]
    pname = p["path_with_namespace"]
    fb = gitlab.get(f"projects/{pid}/repository/branches/{from_branch}", raises=False)
    if fb is None:
        log.error(f"project {pname} is missing source branch {from_branch}")
        return
    r = gitlab.get(f"projects/{pid}/repository/branches/{to_branch}", raises=False)
    if r is not None:
        if force:
            log.info(f"target branch {to_branch} already exists, deleting due to force")
            gitlab.delete(f"projects/{pid}/protected_branches/{to_branch}")
            gitlab.delete(f"projects/{pid}/repository/branches/{to_branch}")
        else:
            log.info(f"project {pname} already has a branch named {to_branch}")
            return False
    log.info(f"renaming branch for project {pname}")

    if fb["protected"]:
        r = gitlab.get(f"projects/{pid}/protected_branches/{from_branch}")
        protected_params = {
            "push_access_level": r["push_access_levels"][0]["access_level"],
            "merge_access_level": r["merge_access_levels"][0]["access_level"],
            "allow_force_push": r["allow_force_push"],
            "code_owner_approval_required": r["code_owner_approval_required"],
        }

    log.info(f"creating branch {to_branch}")
    gitlab.post(
        f"projects/{pid}/repository/branches",
        params={"branch": to_branch, "ref": from_branch},
    )

    if fb["protected"]:
        log.info(f"protecting branch {to_branch}")
        gitlab.post(
            f"projects/{pid}/protected_branches",
            params={
                **protected_params,
                "name": to_branch,
            },
        )

    log.info(f"changing default branch to {to_branch}")
    gitlab.put(f"projects/{pid}", params={"default_branch": to_branch})

    if p["merge_requests_enabled"]:
        for mr in gitlab.list(
            f"projects/{pid}/merge_requests",
            params={
                "state": "opened",
                "scope": "all",
                "target_branch": from_branch,
            },
        ):
            mrid = mr["iid"]
            log.info(f"updating merge request {mrid}")
            gitlab.put(
                f"projects/{pid}/merge_requests/{mrid}",
                params={"target_branch": to_branch},
            )

    if p["jobs_enabled"]:
        for ps in gitlab.list(f"projects/{pid}/pipeline_schedules"):
            if ps["ref"] != from_branch:
                continue
            psid = ps["id"]
            log.info(f"updating pipeline schedule {psid}")
            gitlab.put(
                f"projects/{pid}/pipeline_schedules/{psid}", params={"ref": to_branch}
            )

    for hook in gitlab.list(f"projects/{pid}/hooks"):
        if hook["push_events_branch_filter"] != from_branch:
            continue
        hookid = hook["id"]
        log.info(f"updating hook {hookid}")
        gitlab.put(
            f"projects/{pid}/hooks/{hookid}",
            params={"push_events_branch_filter": to_branch},
        )

    if fb["protected"]:
        log.info(f"unprotecting branch {from_branch}")
        gitlab.delete(f"projects/{pid}/protected_branches/{from_branch}")

    log.info(f"deleting branch {from_branch}")
    gitlab.delete(f"projects/{pid}/repository/branches/{from_branch}")

    log.info(f"preventing pushes to branch {from_branch}")
    gitlab.post(
        f"projects/{pid}/protected_branches",
        params={
            "name": from_branch,
            "push_access_level": 0,
            "merge_access_level": 0,
            "allow_force_push": False,
        },
    )
    return True


class Gitlab:
    dry_run = False

    def __init__(self, session, base_url):
        self.session = session
        self.base_url = base_url

    def _make_url(self, resource):
        return self.base_url + "/api/v4/" + resource.lstrip("/")

    def request(self, method, resource, *, raises=True, **kw):
        url = self._make_url(resource)
        if method not in {"GET", "HEAD"} and self.dry_run:
            log.debug(f"[dry run] {method} {resource}")
            return
        r = self.session.request(method, url, **kw)
        if raises and not r.ok:
            log.error(
                f"invalid response for method {method}, url {url},"
                f" status={r.status_code}, body={r.text}"
            )
            r.raise_for_status()
        return r

    def list(self, resource, *, params=None, **kw):
        url = self._make_url(resource)
        while True:
            r = self.session.get(url, params=params, **kw)
            r.raise_for_status()
            items = r.json()
            for item in items:
                yield item
            if not items or "next" not in r.links:
                break
            url = r.links["next"]["url"]
            params = None

    def _make_request(method):
        def execute(self, resource, **kw):
            r = self.request(method, resource, **kw)
            if r and r.ok and r.status_code == 200:
                return r.json()

        return execute

    get = _make_request("GET")
    post = _make_request("POST")
    put = _make_request("PUT")
    delete = _make_request("DELETE")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="https://gitlab.com")
    parser.add_argument("--from", dest="from_", default="master")
    parser.add_argument("--to", default="main")
    parser.add_argument("-p", "--project")
    parser.add_argument("-n", "--namespace")
    parser.add_argument("-x", "--exclude-project", action="append")
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s:%(levelname)s %(message)s",
    )
    log.setLevel(logging.DEBUG)

    if args.project and not args.namespace:
        raise ValueError("must specify --namespace with --project")

    http = requests.Session()
    if token := os.getenv("GITLAB_TOKEN"):
        http.headers["private-token"] = token
    gitlab = Gitlab(http, args.base_url)
    gitlab.dry_run = args.dry_run
    params = {"archived": "no"}
    renamed_projects = []
    for p in gitlab.list("projects", params=params):
        pname = p["path_with_namespace"]
        if args.namespace and p["namespace"]["path"] != args.namespace:
            continue
        if args.project and p["path"] != args.project:
            continue
        if p["path_with_namespace"] in args.exclude_project:
            log.info(f"skipping {pname}, explicitly excluded")
            continue
        if p["default_branch"] == args.to:
            log.info(f"project {pname} already has correct default branch")
            continue
        try:
            result = rename_default_branch(
                gitlab, p, from_branch=args.from_, to_branch=args.to, force=args.force
            )
            if result:
                renamed_projects.append(p)
        except Exception:
            log.exception(f"failed renaming default branch on project {pname}")
    print("Renamed branches:")
    for p in renamed_projects:
        print("  " + p["path_with_namespace"])
    usage = f"""
        Apply locally:
          git branch -m {args.from_} {args.to}
          git fetch origin
          git branch -u origin/{args.to} {args.to}
          git remote set-head origin -a
    """
    print(dedent(usage).strip())


if __name__ == "__main__":
    raise SystemExit(main())
