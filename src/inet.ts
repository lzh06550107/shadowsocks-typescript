export function inet_ntop(a: Buffer): string | false {
  // IPv4 to string representation
  if (a.length === 4) {
    return [
      a[0], a[1], a[2], a[3]
    ].join('.');
  }
  // IPv6 to string representation
  else if (a.length === 16) {
    const c: string[] = [];
    let m = '';

    for (let i = 0; i < 16; i += 2) {
      let group = a.slice(i, i + 2).toString('hex');
      // Replace leading zeros
      while (group.length > 1 && group.charAt(0) === '0') {
        group = group.slice(1);
      }
      c.push(group);
    }

    return c.join(':').replace(/((^|:)0(?=:|$))+:?/g, (t) => {
      m = (t.length > m.length) ? t : m;
      return t;
    }).replace(m || ' ', '::');
  }
  // Invalid length
  else {
    return false;
  }
}

// Example usage
const ipv4 = Buffer.from([127, 0, 0, 1]);
console.log(inet_ntop(ipv4)); // Outputs: '127.0.0.1'

const ipv6 = Buffer.from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
console.log(inet_ntop(ipv6)); // Outputs: '::1'

