"""Create a new release tag with CalVer format."""
import datetime
import operator
import os
from pathlib import Path

import git
from packaging import version


def get_repo() -> git.Repo:
    """Get the git repo for the current project."""
    return git.Repo(Path(__file__).parent.parent)


def is_already_tagged(repo: git.Repo) -> bool:
    """Check if the current commit is already tagged."""
    return repo.git.tag(points_at="HEAD")


def should_skip_release(repo: git.Repo) -> bool:
    """Check if the commit message contains [skip release]."""
    commit_message = repo.head.commit.message.split("\n")[0]
    return "[skip release]" in commit_message


def get_new_version(repo: git.Repo) -> str:
    """Get the new version number."""
    latest_tag = max(repo.tags, key=operator.attrgetter("commit.committed_datetime"))
    last_version = version.parse(latest_tag.name)
    now = datetime.datetime.now(tz=datetime.timezone.utc)
    patch = (
        last_version.micro + 1
        if last_version.major == now.year and last_version.minor == now.month
        else 0
    )
    return f"{now.year}.{now.month}.{patch}"


def set_author(repo: git.Repo) -> None:
    """Set author information."""
    author_name = repo.head.commit.author.name
    author_email = repo.head.commit.author.email
    os.environ["GIT_AUTHOR_NAME"] = author_name
    os.environ["GIT_AUTHOR_EMAIL"] = author_email
    os.environ["GIT_COMMITTER_NAME"] = author_name
    os.environ["GIT_COMMITTER_EMAIL"] = author_email


def create_tag(repo: git.Repo, new_version: str, release_notes: str) -> None:
    """Create a new tag."""
    set_author(repo)
    repo.create_tag(new_version, message=f"Release {new_version}\n\n{release_notes}")


def push_tag(repo: git.Repo, new_version: str) -> None:
    """Push the new tag to the remote repository."""
    origin = repo.remote("origin")
    origin.push(new_version)


def get_commit_messages_since_last_release(repo: git.Repo) -> str:
    """Get the commit messages since the last release."""
    latest_tag = max(repo.tags, key=operator.attrgetter("commit.committed_datetime"))
    return repo.git.log(f"{latest_tag}..HEAD", "--pretty=format:%s")


def format_release_notes(commit_messages: str, new_version: str) -> str:
    """Format the release notes."""
    header = f"🚀 Release {new_version}\n\n"
    intro = "📝 This release includes the following changes:\n\n"

    commit_list = commit_messages.split("\n")
    formatted_commit_list = [f"- {commit}" for commit in commit_list]
    commit_section = "\n".join(formatted_commit_list)

    footer = (
        "\n\n🙏 Thank you for using this project! Please report any issues "
        "or feedback on the GitHub repository"
        " on 'https://github.com/basnijholt/rsync-time-machine.py'."
    )

    return f"{header}{intro}{commit_section}{footer}"


def main() -> None:
    """Main entry point."""
    repo = get_repo()
    if is_already_tagged(repo):
        print("Current commit is already tagged!")
        return

    if should_skip_release(repo):
        print("Commit message is [skip release]!")
        return

    new_version = get_new_version(repo)
    commit_messages = get_commit_messages_since_last_release(repo)
    release_notes = format_release_notes(commit_messages, new_version)
    print(release_notes)
    create_tag(repo, new_version, release_notes)
    push_tag(repo, new_version)
    # Write the output version to the GITHUB_OUTPUT environment file
    with open(os.environ["GITHUB_OUTPUT"], "a") as output_file:  # noqa: PTH123
        output_file.write(f"version={new_version}\n")
    print(f"Created new tag: {new_version}")


if __name__ == "__main__":
    main()
