from app.gmail.client import GmailClient


class FakeRequest:
    def __init__(self, response):
        self.response = response

    def execute(self):
        return self.response


class FakeMessages:
    def __init__(self):
        self.calls = []

    def list(self, **kwargs):
        self.calls.append(kwargs)
        if kwargs.get("pageToken") is None:
            return FakeRequest({"messages": [{"id": "1"}], "nextPageToken": "next"})
        return FakeRequest({"messages": [{"id": "2"}]})


class FakeHistory:
    def __init__(self):
        self.calls = []

    def list(self, **kwargs):
        self.calls.append(kwargs)
        if kwargs.get("pageToken") is None:
            return FakeRequest(
                {
                    "history": [{"messagesAdded": [{"message": {"id": "m1", "threadId": "t1"}}]}],
                    "nextPageToken": "next-history",
                    "historyId": "200",
                }
            )
        return FakeRequest(
            {
                "history": [{"messagesAdded": [{"message": {"id": "m2", "threadId": "t2"}}]}],
                "historyId": "201",
            }
        )


class FakeUsers:
    def __init__(self, messages, history):
        self._messages = messages
        self._history = history

    def messages(self):
        return self._messages

    def history(self):
        return self._history


class FakeService:
    def __init__(self):
        self.messages_resource = FakeMessages()
        self.history_resource = FakeHistory()

    def users(self):
        return FakeUsers(self.messages_resource, self.history_resource)


def test_list_candidates_reads_multiple_pages():
    service = FakeService()
    client = GmailClient(service=service)

    messages = client.list_candidates("in:inbox", max_results=20, max_pages=5)

    assert messages == [{"id": "1"}, {"id": "2"}]
    assert len(service.messages_resource.calls) == 2
    assert service.messages_resource.calls[1]["pageToken"] == "next"


def test_list_history_reads_multiple_pages():
    service = FakeService()
    client = GmailClient(service=service)

    history, history_id = client.list_history(start_history_id="100", max_pages=5)

    assert history == [
        {"messagesAdded": [{"message": {"id": "m1", "threadId": "t1"}}]},
        {"messagesAdded": [{"message": {"id": "m2", "threadId": "t2"}}]},
    ]
    assert history_id == "201"
    assert service.history_resource.calls[0]["startHistoryId"] == "100"
    assert service.history_resource.calls[1]["pageToken"] == "next-history"
