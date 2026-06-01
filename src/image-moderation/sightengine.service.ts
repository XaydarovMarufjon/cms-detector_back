import { Injectable, Logger } from '@nestjs/common';
import axios from 'axios';

export interface SightengineRaw {
  status: string;
  error?: { type: string; code: number; message: string };
  nudity?: {
    sexual_activity?: number;
    sexual_display?: number;
    erotica?: number;
    very_suggestive?: number;
    suggestive?: number;
    mildly_suggestive?: number;
    none?: number;
  };
  gore?: {
    prob?: number;
    classes?: Record<string, number>;
    type?: Record<string, number>;
  };
  offensive?: {
    nazi?: number;
    confederate?: number;
    supremacist?: number;
    terrorist?: number;
    middle_finger?: number;
    religious_symbol?: number;
    religious_symbol_islam?: number;
    religious_symbol_christianity?: number;
    religious_symbol_judaism?: number;
    religious_symbol_hinduism?: number;
    religious_symbol_buddhism?: number;
    religious_symbol_sikhism?: number;
    [k: string]: number | undefined;
  };
}

export interface ImageVerdict {
  sexualScore: number;
  violentScore: number;
  religiousScore: number;
  categories: string[];
  flagged: boolean;
  raw: SightengineRaw | null;
  error?: string;
}

const ENDPOINT = 'https://api.sightengine.com/1.0/check.json';
const MODELS = 'nudity-2.1,gore-2.0,offensive-2.0';
const FLAG_THRESHOLD = 0.55;

@Injectable()
export class SightengineService {
  private readonly logger = new Logger(SightengineService.name);
  private readonly user = process.env.SIGHTENGINE_API_USER || '';
  private readonly secret = process.env.SIGHTENGINE_API_SECRET || '';

  isConfigured(): boolean {
    return !!(this.user && this.secret);
  }

  async checkImage(imageUrl: string): Promise<ImageVerdict> {
    if (!this.isConfigured()) {
      return this.empty('Sightengine API credentials missing');
    }
    try {
      const res = await axios.get<SightengineRaw>(ENDPOINT, {
        timeout: 30_000,
        params: {
          url: imageUrl,
          models: MODELS,
          api_user: this.user,
          api_secret: this.secret,
        },
        validateStatus: () => true,
      });

      if (res.status !== 200 || res.data?.status !== 'success') {
        const msg = res.data?.error?.message || `HTTP ${res.status}`;
        return this.empty(msg);
      }

      return this.parse(res.data);
    } catch (e) {
      return this.empty((e as Error).message);
    }
  }

  private parse(d: SightengineRaw): ImageVerdict {
    const sexual = this.maxNudity(d.nudity);
    const violent = this.maxViolent(d.gore);
    const religious = this.maxReligious(d.offensive);

    const categories: string[] = [];
    if (sexual >= FLAG_THRESHOLD) categories.push('sexual');
    if (violent >= FLAG_THRESHOLD) categories.push('violent');
    if (religious >= FLAG_THRESHOLD) categories.push('religious');

    return {
      sexualScore: sexual,
      violentScore: violent,
      religiousScore: religious,
      categories,
      flagged: categories.length > 0,
      raw: d,
    };
  }

  private maxNudity(n?: SightengineRaw['nudity']): number {
    if (!n) return 0;
    return Math.max(
      n.sexual_activity ?? 0,
      n.sexual_display ?? 0,
      n.erotica ?? 0,
      n.very_suggestive ?? 0,
    );
  }

  private maxViolent(g?: SightengineRaw['gore']): number {
    if (!g) return 0;
    const cls = g.classes ?? {};
    const top = g.type ?? {};
    return Math.max(
      g.prob ?? 0,
      cls['very_bloody'] ?? 0,
      cls['slightly_bloody'] ?? 0,
      cls['body_organ'] ?? 0,
      cls['serious_injury'] ?? 0,
      cls['superficial_injury'] ?? 0,
      cls['corpse'] ?? 0,
      cls['skull'] ?? 0,
      cls['weapon'] ?? cls['firearm'] ?? 0,
      top['very_bloody'] ?? 0,
    );
  }

  private maxReligious(o?: SightengineRaw['offensive']): number {
    if (!o) return 0;
    const keys = Object.keys(o).filter(k => k.startsWith('religious_symbol'));
    let max = 0;
    for (const k of keys) {
      const v = o[k];
      if (typeof v === 'number' && v > max) max = v;
    }
    return Math.max(max, o.terrorist ?? 0, o.nazi ?? 0);
  }

  private empty(error: string): ImageVerdict {
    return {
      sexualScore: 0,
      violentScore: 0,
      religiousScore: 0,
      categories: [],
      flagged: false,
      raw: null,
      error,
    };
  }
}
