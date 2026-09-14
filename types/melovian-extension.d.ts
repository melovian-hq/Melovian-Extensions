// Ambient types for Melovian extension scripts.
//
// A script package declares a top-level function named `register`. The
// sandbox calls it once with the extension API. Everything not listed
// here is unavailable: no network, no DOM, no storage, no timers with
// string arguments.
//
// Reference this file with:
//   /// <reference path="../../types/melovian-extension.d.ts" />

declare namespace melovian {
  interface TrackMatch {
    genreContains?: string;
    artistContains?: string;
    albumContains?: string;
    titleContains?: string;
    titleRegex?: string;
    tagEquals?: string;
    minRating?: number;
    isLocal?: boolean;
  }

  interface TrackDecoration {
    progressColor?: string;
    progressGradient?: string;
    progressThumbUrl?: string;
    progressParticleUrl?: string;
    icon?: string;
    iconUrl?: string;
    titlePrefix?: string;
    coverOverlayIcon?: string;
    playerTheme?: string;
  }

  interface TrackRule {
    match: TrackMatch;
    decoration: TrackDecoration;
  }

  interface Track {
    id?: string;
    title?: string;
    artist?: string;
    album?: string;
    genre?: string;
  }

  interface DecorateTrackContext {
    track: Track;
    isLocal: boolean;
    genre?: string;
    rating?: number;
    tags?: string[];
  }

  interface ExtensionAPI {
    registerTrackRule(rule: TrackRule): void;
    decorateTrack(ctx: DecorateTrackContext): TrackDecoration | null | undefined;
  }
}

declare function register(api: melovian.ExtensionAPI): void;
