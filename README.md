porlock
=======
Monitor event logs for potentially fraudulent activity

Premise
--------------
Oftentimes, specific events in and of themselves don't indicate a
risk to your systems.  However, when viewed in the context of surrounding
events, we can identify potentially risky behavior.

Take the following scenario, represented by the events below: 
- A user calls customer service and requests and one time token for login.
- The user logs in, and the system requires a password update
- A few days later, the user comes to the site (from a new IP) and requests a password reset
- The user proceeds to change their password

```
Event: otp_login, date: 2022-11-01 13:43:17 EST, user_id: 1, ip: 10.0.0.1
Event: password_change, date: 2022-11-01 13:45:53 EST, user_id: 1, ip: 10.0.0.1
Event: password_reset, date: 2022-11-07 17:31:22 EST, user_id: 1, ip: 192.168.0.1
Event: password_change, date: 2022-11-07 17:33:11 EST, user_id: 1, ip: 192.168.0.1
```

None of the above events, in isolation, look particularly risky, and while it
is possible that the user simply forgot their new password, when
viewed along with other events, this sequence of events points to a potential account hijack.

porlock provides a rule framework to help make finding these events and flagging them
possible.  By identifying events, and subsequent matching events, porlock parses
logs over a specified time period to flag risky behavior.

Basic Rules
--------------

- Rules are written in a simple list format 
  - Note: future versions may support yaml rules

```

    [
       "Password Change After OTP Login",
       "otp login",
       "followed by",
       "any",
       ["password change"],
       "after",
       "2d",
       "user",
       ["password change"],
       "before",
       "1h",
       "14d",
       "30d"
    ]
```

- `Rule Name`: A human readable description of the rule
- `Event Name`: The name of the initial event to search for
- `When`: `followed by` or `preceded by` (Currently only `followed by` is supported)
- `Match`: What type of match to `any`, `all`, `none`, `one`
- `Matching Events`: a list of events to match
- `Period When`: whether or not this event should happen `before` or `after` the `Period` parameter
- `Period`: How long `after` the initial event to start looking (or when to stop looking for `before`)
- `Identifier`: The field to match events on.  This is typically either a user id, email, or IP address
- `Secondary Event`: For future use
- `Secondary Period When`: For future use
- `Secondary Period`: For future use
- `Match time frame`: The time frame after (for `followed by`) the initial event occurred to check for matching events
- `Log time frame`: For future use; The time frame to return all events for a particular `identifier` from the logs

## Parameters
### When
- `followed by` - the matching events should come after the initial event
- `preceded by` - the matching events should come before the initial event (Note: This is still a work in progress)

### Match
- `any` - can match any of the listed events
- `all` - must match all of the listed events
- `none` - must match none of the listed events
- `one` - must match one and only one of the listed events

### Period When
- `before` - indicates to check all events prior to the `Period` parameter
- `after`- indicates to check all events after to the `Period` parameter

### Period
- The period should be specified by a number followed by one of `s` (seconds), `m` (minutes), `h` (hours), `d` (days), or `w` (weeks)