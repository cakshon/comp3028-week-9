import jwt from 'jsonwebtoken';
const token = process.argv[2];
console.log(jwt.decode(token, { complete: true }));
