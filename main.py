# Copyright 2020 Alexander Lim
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import base64
import configparser
import pickle
import os.path
import praw
import time
import urllib
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from email.mime.text import MIMEText


class GmailNotifier:
    """Sends out an email for matching submissions."""

    def __init__(self, gmail, config):
        """Initialize a GmailNotifier

        Args:
            gmail: A Gmail resource returned from
                   googleapiclient.discovery.build
            config: Provides the key/values "from_email" and "to_email".
        """
        self.gmail = gmail
        self.from_email = config["from_email"]
        self.to_email = config["to_email"]

    def handle_matches(self, matches, submission):
        """Send out an email for a matching submission.

        Args:
            matches: A list of words that were found in the submission.
            submission: A Reddit post returned by PRAW.
        """
        message = self.create_message(
            self.from_email, self.to_email, ", ".join(matches), submission.url
        )
        try:
            message = (
                self.gmail.users().messages().send(userId="me", body=message).execute()
            )
        except urllib.error.HTTPError:
            print("An error occurred")

    def create_message(self, sender, to, subject, message_text):
        """Create a message for an email.

        Args:
            sender: Email address of the sender.
            to: Email address of the receiver.
            subject: The subject of the email message.
            message_text: The text of the email message.

        Returns:
            An object containing a base64url encoded email object.
        """
        message = MIMEText(message_text)
        message["to"] = to
        message["from"] = sender
        message["subject"] = subject
        return {
            "raw": base64.urlsafe_b64encode(message.as_string().encode("utf-8")).decode(
                "utf-8"
            )
        }


class InMemorySubmissionIDCache:
    """Stores seen submissions in memory."""

    seen_comment_ids = set()

    def is_submission_id_seen(self, submission_id):
        return submission_id in self.seen_comment_ids

    def store_seen_submission_id(self, submission_id):
        self.seen_comment_ids.add(submission_id)


class DiskSubmissionIDCache:
    """Writes seen submissions to a file."""

    seen_comment_ids = set()

    def __init__(self, path):
        """Initialize a DiskSubmissionIDCache.

        Args:
            path: The path to a cache file.
        """
        self.path = path
        try:
            with open(self.path, "r") as f:
                for line in f:
                    self.seen_comment_ids.add(line.rstrip())
            print(f"{len(self.seen_comment_ids)} comments seen")
        except OSError as error:
            print("Couldn't open file {0}").format(error.strerror)
            pass

    def is_submission_id_seen(self, submission_id):
        return submission_id in self.seen_comment_ids

    def store_seen_submission_id(self, submission_id):
        self.seen_comment_ids.add(submission_id)
        with open(self.path, "w") as f:
            # TODO: Just append each one to the end, rather than rewriting the
            # whole thing.
            f.write("\n".join(self.seen_comment_ids))


def scan(reddit, keywords, cache, notifier):
    for submission in reddit.subreddit("mechmarket").search(
        "flair:selling", sort="new"
    ):
        if cache.is_submission_id_seen(submission.id):
            continue
        matches = keywords_in(keywords, submission)
        if matches:
            print(matches)
            print(submission.title)
            print(submission.url)
            if notifier is not None:
                notifier.handle_matches(matches, submission)
        cache.store_seen_submission_id(submission.id)


def keywords_in(keywords, submission):
    """Searches the submission's text and title for any of the given keywords.

    Args:
        keywords: A list of strings to search for.
        submission: A Reddit post to look in.

    Returns:
        A list of the keywords that appeared in the submission, if there are
        any.
    """
    matches = []
    for keyword in keywords:
        if (
            keyword in submission.selftext.lower()
            or keyword in submission.title.lower()
        ):
            matches.append(keyword)
    return matches


def login_to_gmail():
    """Login to Gmail and return the resource."""
    SCOPES = ["https://www.googleapis.com/auth/gmail.send"]
    creds = None
    # The file token.pickle stores the user's access and refresh tokens, and is
    # created automatically when the authorization flow completes for the first
    # time.
    if os.path.exists("token.pickle"):
        with open("token.pickle", "rb") as token:
            creds = pickle.load(token)
    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file("credentials.json", SCOPES)
            creds = flow.run_local_server(port=0)
        # Save the credentials for the next run
        with open("token.pickle", "wb") as token:
            pickle.dump(creds, token)

    return build("gmail", "v1", credentials=creds)


def main():
    config = configparser.ConfigParser()
    config.read("config.ini")

    reddit_config = config["reddit"]
    reddit = praw.Reddit(
        client_id=reddit_config["client_id"],
        client_secret=reddit_config["client_secret"],
        user_agent=reddit_config["user_agent"],
    )

    # Read keywords in from a file. Each line is one keyword.
    keywords = []
    with open("keywords.txt", "r") as f:
        for line in f:
            keywords.append(line.rstrip())

    print(keywords)

    # You can swap the comments on the two lines below to store the seen comment
    # IDs in-memory instead.
    cache = DiskSubmissionIDCache("cache.txt")
    # cache = InMemorySubmissionIDCache()

    notifier = GmailNotifier(login_to_gmail(), config["gmail"])
    # notifier = None

    while True:
        scan(reddit, keywords, cache, notifier)
        # Be careful with this, there's a rate limit.
        time.sleep(5)


if __name__ == "__main__":
    main()
