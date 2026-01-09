# OBS Battle Sound Setup (Reliable)

OBS Browser Source audio is unreliable because OBS uses an embedded Chromium that can block HTML audio even after clicks.
This project intentionally makes the **/overlay** page **visual-only**.

## What to add in OBS

### 1) Browser Source (visual overlay)
- URL: `https://YOUR_DOMAIN/overlay`
- Width: `450`
- Height: `450`

### 2) Media Source (battle sound)
1. Download the battle sound file from your bot:
   - `https://YOUR_DOMAIN/sounds/wild_battle.mp3`

2. In OBS, add a **Media Source**:
- Local File: the `wild_battle.mp3` you downloaded
- ✅ Loop
- ✅ Restart playback when source becomes active
- ✅ Close file when inactive

## How to start/stop sound automatically
The easiest method is to put the Media Source in the same scene as the overlay and toggle its visibility:

- When a Pokémon is active, make the Media Source visible (sound plays looped).
- When no Pokémon is active, hide the Media Source (sound stops).

If you use a tool like Streamer.bot / OBS WebSocket, poll:
- `GET /overlay/state`

It returns:
```json
{ "active": true, "spawn": { ... } }
```

Use `active` to show/hide the Media Source automatically.
