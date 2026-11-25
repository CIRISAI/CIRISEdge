# The presence blob: the lowest tier of a call

**Status:** design locked by the owner, 2026-11-25. Not implemented. The wire
layout below is edge's proposal; the normative text belongs to the Constitution.

## Why

The goal is a thousand people in one live call, and later far more, with no
central media server. A member's download must scale with the streams it chooses
to receive, never with the size of the room. People register about four others
as individuals at a time and read everyone else as a crowd: its overall motion,
its colour, a sudden change. So the room needs a tier below the lowest audio and
video layer that says "this person is here, and this is roughly what they are
doing", at a cost small enough to receive for hundreds of people at once.

## The blob

| | Locked value | Why |
|---|---|---|
| Size | 16 × 16 pixels | Recognisable as a face blob or a pixel-art avatar. Smaller saves little: per-chunk overhead dominates. |
| Colour | 16 colours, the palette carried in every frame | 128 B of pixels (4 bits each) + 48 B of palette (16 × RGB) = 176 B. A 256-colour 16 × 16 frame is 256 B raw and does not fit the smallest path. |
| Frames | Each frame self-contained | No keyframes. Any one frame draws, a lost frame costs nothing, a late joiner sees the member on the next frame. |
| Rate | ~1 frame/s; bursts to ~5 frames/s for a few seconds on activity; a refresh every ~5 s when nothing changes | A crowd is read as motion and change, not as smooth video. |
| Source | A blob of the member's camera feed, or a pixel-art avatar the member animates directly | The member chooses. |

One frame is one signed chunk. It must fit the smallest relayed path, whose
chunk payload budget is 246 B (a 400 B relayed leg less ~154 B of per-chunk
overhead, most of it the publisher's signature). 176 B plus a small header fits.

**Cost:** ~330 B per frame on the wire, so ~2.6 kbit/s per blob at 1 frame/s.

## How many at once

**256 visible by default**, chosen by the receiver between 64 and 1024.

| Visible | Download at 1 frame/s |
|---|---|
| 64 | ~170 kbit/s |
| 256 | ~0.7 Mbit/s |
| 1024 | ~2.7 Mbit/s |

256 is past the point where tiles are read one by one, costs under a megabit,
and can be raised later.

## What this needs from the call tree

- **Per-stream subscribe and unsubscribe.** A member receives the blobs it shows
  and no others. Today every member receives every stream.
- **Offers only to subscribers.** Today every member offers every stream it
  relays to every member every second.
- **A stream nobody watches costs almost nothing.**
- A relay forwards a blob to its children as it forwards any chunk. At two to
  four children that is ~5–10 kbit/s of upload per blob relayed.

## Open

- About 60 % of a blob's cost is the per-chunk signature and framing. Bundling
  many members' blobs into one packet at a relay would cut that, and conflicts
  with each publisher signing its own chunk. A design decision, not taken.
- Signature checks: 256 blobs at 1 frame/s is 256 checks a second. Unmeasured on
  a phone.
- For rooms far above what one screen shows, a relay composing many members into
  one low-resolution feed is a possible later design. Not planned.
- The exact header (stream kind, frame counter, activity hint) and how the
  palette is ordered.
