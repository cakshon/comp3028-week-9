// Classroom-only fixture, not a real account database.
const users = [
  { id: 1, username: 'brad', password: 'Student123!',
    role: 'student' },
  { id: 2, username: 'alex', password: 'Admin123!',
    role: 'admin' }
];
export class UserService {
  async validUserCredentials(username, password) {
    if (typeof username !== 'string' ||
        typeof password !== 'string' || !username || !password) {
      return null;
    }
    const match = users.find(user =>
      user.username === username && user.password === password
    );
    if (!match) return null;
    // Do not return the password to the route handler.
    return { id: match.id, username: match.username,
      role: match.role };
  }
}
