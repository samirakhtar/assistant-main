import axios from "axios";

const categories = {
  ctr: "85",
  "command and control": "64,65",
  cryptomining: "150",
  "dns tunneling vpn": "110",
  "dynamic dns": "61",
  malware: "66",
  "newly seen domains": "108",
  phishing: "68",
  "potentially harmful": "109",
  "secure x": "87",
  adult: "161",
  advertisements: "27",
  alchol: "1",
  "animals and pets": "19",
  arts: "111",
  astrology: "112",
  auctions: "2",
};

export class NetworkService {
  baseUrl = "https://api.umbrella.com/deployments/v2/networks";
  _token = "";

  setToken(value: string) {
    this._token = value;
  }

  async listNetworkDeployments() {
    const url = new URL(this.baseUrl);
    const res = await axios.get(url.toString());
    return res.data;
  }

  async createNetworkDeployment({
    name,
    ipAddress,
    prefixLength,
    isDynamic,
    status,
  }: {
    name: string;
    ipAddress: string;
    prefixLength: number;
    isDynamic: boolean;
    status: string;
  }) {
    const url = new URL(this.baseUrl);
    const res = await axios.post(
      url.toString(),
      {
        name,
        ipAddress,
        prefixLength,
        isDynamic,
        status,
      },
      {
        headers: {
          Authorization: `Bearer ${this._token}`,
        },
      },
    );
    return res.data;
  }

  async updateNetworkDeployment({
    id,
    name,
    ipAddress,
    prefixLength,
    isDynamic,
    status,
  }: {
    id: string;
    name?: string;
    ipAddress?: string;
    prefixLength?: number;
    isDynamic?: boolean;
    status?: string;
  }) {
    const url = new URL(`${this.baseUrl}/${id}`);
    const res = await axios.put(
      url.toString(),
      {
        name,
        ipAddress,
        prefixLength,
        isDynamic,
        status,
      },
      {
        headers: {
          Authorization: `Bearer ${this._token}`,
        },
      },
    );
    return res.data;
  }

  async getIdentityId({ search }: { search: string }) {
    const url = new URL(
      `https://api.umbrella.com/reports/v2/identities?search=*${encodeURIComponent(`%${search.toLowerCase()}%`)}*&limit=10&offset=0&from=0&to=0&identitytypes=`,
    );
    const res = await axios.get(url.toString(), {
      headers: {
        Authorization: `Bearer ${this._token}`,
      },
    });
    console.log(JSON.stringify(res.data, null, 2));
    if (!res.data.data?.length) {
      return { error: "No identity found. Check name or email with the user" };
    }

    if (res.data.data.length > 1) {
      return {
        error:
          "Multiple identities found. Please ask the user to select one of these",
        data: res.data.data,
      };
    }

    return { id: res.data.data[0].id, label: res.data.data[0].label };
  }

  async lookupActivitiesSearch({
    startDate,
    endDate,
    domain,
    category,
    verdict,
    identityids,
  }: {
    startDate: string;
    endDate: string;
    domain: string;
    category: string;
    verdict: string;
    identityids: string;
  }) {
    const ids = identityids?.split(",");
    if (ids?.length && ids.some((id) => !Number.parseInt(id))) {
      return {
        error:
          "Invalid identity ids provided. If names or emails are provided, the assistant must fecth the ids using getIdentityId tool first",
      };
    }
    const _categories = category?.split(",");
    if (
      _categories?.length &&
      _categories.some((cat) => !(cat.toLowerCase() in categories))
    ) {
      return {
        error:
          "Invalid categories provided. Please provide one or more of the following: ctr, command and control, cryptomining, dns tunneling vpn, dynamic dns, malware, newly seen domains, phishing, potentially harmful, secure x, adult, advertisements, alchol, animals and pets, arts, astrology, auctions",
      };
    }
    const url = new URL(
      `https://api.umbrella.com/reports/v2/activity/dns?order=desc&from=${new Date(startDate).getTime()}&to=${new Date(endDate).getTime()}&domain=${domain || ""}&categories=${
        category
          ?.split(",")
          .map((cat) => (categories as any)[cat.toLowerCase()]) || ""
      }&verdict=${verdict || ""}&limit=50&identityids=${identityids || ""}`,
    );
    const res = await axios.get(url.toString(), {
      headers: {
        Authorization: `Bearer ${this._token}`,
      },
    });
    return res.data.data.map((activity: any) => ({
      domain: activity.domain,
      verdict: activity.verdict,
      identities: activity.identities,
      externalIp: activity.externalip,
      blockedapplications: activity.blockedapplications,
      threats: activity.threats,
    }));
  }

  async getNetworkDeployment({ id }: { id: string }) {
    const url = new URL(`${this.baseUrl}/${id}`);
    const res = await axios.get(url.toString(), {
      headers: {
        Authorization: `Bearer ${this._token}`,
      },
    });
    return res.data;
  }

  async deleteNetworkDeployment({ id }: { id: string }) {
    const url = new URL(`${this.baseUrl}/${id}`);
    const res = await axios.delete(url.toString(), {
      headers: {
        Authorization: `Bearer ${this._token}`,
      },
    });
    return res.data;
  }

  async listInfectedLookups({
    startDate,
    endDate,
    identityids,
  }: {
    startDate: string;
    endDate: string;
    identityids: string;
  }) {
    if (!startDate) {
      return { error: "No start date provided. Ask the user for a start date" };
    }
    if (!endDate) {
      return { error: "No end date provided. Ask the user for an end" };
    }
    const ids = identityids?.split(",");
    if (ids?.length && ids.some((id) => !Number.parseInt(id))) {
      return {
        error:
          "Invalid identity ids provided. If names or emails are provided, the ids must be fetched using getIdentityId tool first",
      };
    }
    const res = await axios.get(
      `https://api.umbrella.com/reports/v2/activity/dns?from=${new Date(startDate).getTime()}&to=${new Date(endDate).getTime()}&limit=50&verdict=blocked&order=desc${
        identityids ? `&identityids=${identityids}` : ""
      }`,
      {
        headers: {
          Authorization: `Bearer ${this._token}`,
        },
      },
    );

    return res.data.data.map((activity: any) => ({
      blockedapplications: activity.blockedapplications,
      identities: activity.identities,
      domain: activity.domain,
    }));
  }

  async getTopThreats({
    startDate,
    endDate,
  }: {
    startDate: number;
    endDate: number;
  }) {
    if (!startDate) {
      return { error: "No start date provided." };
    }
    if (!endDate) {
      return { error: "No end date provided." };
    }
    const res = await axios.get(
      `https://api.umbrella.com/reports/v2/top-threats?from=${new Date(startDate).getTime()}&to=${new Date(endDate).getTime()}&limit=50`,
      {
        headers: {
          Authorization: `Bearer ${this._token}`,
        },
      },
    );

    if (!res.data.data.length) {
      return { message: "No data found for current date range" };
    }

    return res.data.data;
  }

  async getTopThreatTypes({
    startDate,
    endDate,
  }: {
    startDate: number;
    endDate: number;
  }) {
    if (!startDate) {
      return { error: "No start date provided." };
    }
    if (!endDate) {
      return { error: "No end date provided." };
    }
    const res = await axios.get(
      `https://api.umbrella.com/reports/v2/top-threat-types?from=${new Date(startDate).getTime()}&to=${new Date(endDate).getTime()}&limit=50`,
      {
        headers: {
          Authorization: `Bearer ${this._token}`,
        },
      },
    );

    if (!res.data.data.length) {
      return { message: "No data found for current date range" };
    }

    return res.data.data;
  }

  async generateToken() {
    const res = await axios.post(
      "https://api.umbrella.com/auth/v2/token",
      {
        grant_type: "client_credentials",
      },
      {
        auth: {
          username: "c647fcbef363419bbef1163560882194",
          password: "a47e5f73d0e64d4cb57335bc091f07d6",
        },
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
      },
    );

    return res.data.access_token;
  }
}
