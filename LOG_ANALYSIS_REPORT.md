# Звіт аналізу журналу

Підсумок сформовано з подій відфільтрованого JSONL-журналу.

```json
{
  "total_events": 26,
  "blocked_connections_and_packets": 4,
  "top_blocked_ips": [
    [
      "127.0.0.1",
      4
    ]
  ],
  "top_blocked_ports": [
    [
      21636,
      1
    ],
    [
      55456,
      1
    ],
    [
      63308,
      1
    ],
    [
      63379,
      1
    ]
  ],
  "rule_hits": [
    [
      1,
      2
    ],
    [
      2,
      2
    ]
  ],
  "repeated_access_attempts": [
    {
      "key": {
        "source_ip": "127.0.0.1",
        "destination_ip": "127.0.0.1",
        "destination_port": 21636,
        "protocol": "TCP"
      },
      "count": 1
    },
    {
      "key": {
        "source_ip": "127.0.0.1",
        "destination_ip": "127.0.0.1",
        "destination_port": 55456,
        "protocol": "UDP"
      },
      "count": 1
    },
    {
      "key": {
        "source_ip": "127.0.0.1",
        "destination_ip": "127.0.0.1",
        "destination_port": 63308,
        "protocol": "TCP"
      },
      "count": 1
    },
    {
      "key": {
        "source_ip": "127.0.0.1",
        "destination_ip": "127.0.0.1",
        "destination_port": 63379,
        "protocol": "UDP"
      },
      "count": 1
    }
  ]
}
```
