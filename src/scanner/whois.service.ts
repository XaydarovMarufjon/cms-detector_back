import { Injectable } from '@nestjs/common';
import axios from 'axios';
import { promises as dns } from 'dns';
import { AlertsService } from '../alerts/alerts.service';

export interface WhoisData {
  domainName:     string | null;
  registrar:      string | null;
  nameServers:    string[];
  status:         string | null;
  creationDate:   string | null;
  updatedDate:    string | null;
  expirationDate: string | null;
  ipAddresses:    string[];
  phone:          string | null;
  raw:            string | null;
}

@Injectable()
export class WhoisService {
  constructor(private readonly alertsService: AlertsService) {}

  async lookup(domain: string, websiteId?: string): Promise<WhoisData> {
    const empty: WhoisData = {
      domainName: null, registrar: null, nameServers: [],
      status: null, creationDate: null, updatedDate: null,
      expirationDate: null, ipAddresses: [], phone: null, raw: null,
    };

    const host = domain.toLowerCase()
      .replace(/^https?:\/\//, '')
      .split('/')[0]
      .replace(/^www\./, '');

    if (!host.endsWith('.uz')) return empty;

    const [ipAddresses, whoisResult] = await Promise.all([
      this.resolveIPs(host),
      this.fetchWhois(host),
    ]);

    const result = { ...whoisResult, ipAddresses };

    // Fire-and-forget alert check
    if (result.expirationDate) {
      this.alertsService.checkExpiry(host, result.expirationDate, websiteId).catch(() => {});
    }

    return result;
  }

  private async resolveIPs(host: string): Promise<string[]> {
    try {
      return await dns.resolve4(host);
    } catch {
      return [];
    }
  }

  private async fetchWhois(host: string): Promise<Omit<WhoisData, 'ipAddresses'>> {
    const empty = {
      domainName: null, registrar: null, nameServers: [],
      status: null, creationDate: null, updatedDate: null,
      expirationDate: null, phone: null, raw: null,
    };

    const url = `https://cctld.uz/whois/?domain=${host}&zone=.uz`;

    try {
      const { data: html } = await axios.get<string>(url, {
        timeout: 12_000,
        headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' },
      });

      const preMatch = html.match(/<pre[^>]*>([\s\S]*?)<\/pre>/i);
      if (!preMatch) return empty;
      const raw = preMatch[1].replace(/<[^>]+>/g, '').trim();

      const get = (key: string): string | null => {
        const m = raw.match(new RegExp(`^\\s*${key}:\\s*(.+)$`, 'im'));
        return m ? m[1].trim() : null;
      };

      const nameServers = raw
        .split('\n')
        .filter(l => /^\s*Name Server:/i.test(l))
        .map(l => {
          const val = l.replace(/^\s*Name Server:\s*/i, '').trim();
          return val.split(/\s+/)[0];
        })
        .filter(ns => ns && !ns.toLowerCase().startsWith('not.defined'));

      const rawPhone = get('Phone') ?? get('phone');
      const phone = rawPhone && !rawPhone.toLowerCase().includes('not.defined') ? rawPhone : null;

      return {
        domainName:     get('Domain Name'),
        registrar:      get('Registrar'),
        nameServers,
        status:         get('Status'),
        creationDate:   get('Creation Date'),
        updatedDate:    get('Updated Date'),
        expirationDate: get('Expiration Date'),
        phone,
        raw,
      };
    } catch {
      return empty;
    }
  }
}
