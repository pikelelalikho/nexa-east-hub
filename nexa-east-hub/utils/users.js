// utils/users.js
import fs from 'fs';
import path from 'path';

// Path to users data file
const usersFilePath = path.join(process.cwd(), 'data', 'users.json');

// Ensure data directory exists
const dataDir = path.join(process.cwd(), 'data');
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

// Initialize users file if it doesn't exist
if (!fs.existsSync(usersFilePath)) {
  const initialUsers = [];
  fs.writeFileSync(usersFilePath, JSON.stringify(initialUsers, null, 2));
}

// Read users from JSON file
export const readUsers = () => {
  try {
    const data = fs.readFileSync(usersFilePath, 'utf8');
    return JSON.parse(data);
  } catch (error) {
    console.error('Error reading users file:', error);
    return [];
  }
};

// Save users to JSON file
export const saveUsers = (users) => {
  try {
    fs.writeFileSync(usersFilePath, JSON.stringify(users, null, 2));
    return true;
  } catch (error) {
    console.error('Error saving users file:', error);
    return false;
  }
};

// Find user by email
export const findUserByEmail = (email) => {
  const users = readUsers();
  return users.find(user => user.email === email);
};

// Find user by ID
export const findUserById = (id) => {
  const users = readUsers();
  return users.find(user => user.id === id);
};

// Add new user
export const addUser = (userData) => {
  const users = readUsers();
  
  // Generate ID if not provided
  if (!userData.id) {
    userData.id = Date.now().toString() + Math.random().toString(36).substr(2, 9);
  }
  
  // Add timestamp
  userData.createdAt = new Date().toISOString();
  userData.updatedAt = new Date().toISOString();
  
  users.push(userData);
  return saveUsers(users) ? userData : null;
};

// Update user
export const updateUser = (id, updateData) => {
  const users = readUsers();
  const userIndex = users.findIndex(user => user.id === id);
  
  if (userIndex === -1) {
    return null;
  }
  
  // Update timestamp
  updateData.updatedAt = new Date().toISOString();
  
  users[userIndex] = { ...users[userIndex], ...updateData };
  return saveUsers(users) ? users[userIndex] : null;
};

// Delete user
export const deleteUser = (id) => {
  const users = readUsers();
  const filteredUsers = users.filter(user => user.id !== id);
  
  if (filteredUsers.length === users.length) {
    return false; // User not found
  }
  
  return saveUsers(filteredUsers);
};

// Check if email exists
export const emailExists = (email) => {
  const users = readUsers();
  return users.some(user => user.email === email);
};

// Get user count
export const getUserCount = () => {
  const users = readUsers();
  return users.length;
};

// Get users by role
export const getUsersByRole = (role) => {
  const users = readUsers();
  return users.filter(user => user.role === role);
};

// Search users
export const searchUsers = (query) => {
  const users = readUsers();
  const searchTerm = query.toLowerCase();
  
  return users.filter(user => 
    user.name?.toLowerCase().includes(searchTerm) ||
    user.email?.toLowerCase().includes(searchTerm) ||
    user.role?.toLowerCase().includes(searchTerm)
  );
};

export default {
  readUsers,
  saveUsers,
  findUserByEmail,
  findUserById,
  addUser,
  updateUser,
  deleteUser,
  emailExists,
  getUserCount,
  getUsersByRole,
  searchUsers
};