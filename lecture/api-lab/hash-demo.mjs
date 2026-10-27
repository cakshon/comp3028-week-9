import bcrypt from 'bcrypt';
const password = 'AliceDemo!42';
const hash1 = await bcrypt.hash(password, 10);
const hash2 = await bcrypt.hash(password, 10);
console.log('Hash 1:', hash1);
console.log('Hash 2:', hash2);
console.log('Same hashes?', hash1 === hash2);
console.log('Correct password?', await bcrypt.compare(password, hash1));
console.log('Wrong password?', await bcrypt.compare('wrong', hash1));
