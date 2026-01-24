/**
 * TypeScript/Node.js configuration - INTENTIONALLY VULNERABLE for testing
 * These patterns should NEVER be used in production
 */

import express, { Request, Response, NextFunction } from 'express';
import { exec, execSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';

// CRITICAL: Hardcoded secrets
const CONFIG = {
  SECRET_KEY: 'super-secret-typescript-key-123',
  JWT_SECRET: 'jwt-weak-secret',
  API_KEY: 'sk-1234567890abcdef',
  DB_PASSWORD: 'admin123',
  AWS_ACCESS_KEY: 'AKIAIOSFODNN7EXAMPLE',
  AWS_SECRET_KEY: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
};

// Database config with hardcoded credentials
interface DatabaseConfig {
  host: string;
  port: number;
  user: string;
  password: string;
  database: string;
}

const dbConfig: DatabaseConfig = {
  host: 'localhost',
  port: 5432,
  user: 'postgres',
  password: 'PostgresPass123!',  // CRITICAL: Hardcoded password
  database: 'myapp'
};

// CRITICAL: Command injection via user input
function pingHost(host: string): void {
  const cmd = `ping -c 4 ${host}`;  // Vulnerable to injection
  exec(cmd, (error, stdout, stderr) => {
    console.log(stdout);
  });
}

// CRITICAL: SQL injection
async function getUser(userId: string): Promise<any> {
  const query = `SELECT * FROM users WHERE id = '${userId}'`;  // SQL injection
  // return db.query(query);
}

// CRITICAL: Path traversal
function readFile(filename: string): string {
  const filepath = path.join('/var/www/uploads', filename);  // Path traversal
  return fs.readFileSync(filepath, 'utf8');
}

// CRITICAL: eval with user input
function calculate(expression: string): any {
  return eval(expression);  // Code injection
}

// CRITICAL: Deserialization (if using certain libraries)
function deserialize(data: string): any {
  // Using node-serialize or similar = RCE
  // return serialize.unserialize(data);
  return JSON.parse(data);  // JSON.parse is safer but check TypeNameHandling
}

// HIGH: SSRF vulnerability
async function fetchUrl(url: string): Promise<Response> {
  return fetch(url);  // User-controlled URL = SSRF
}

// HIGH: Prototype pollution
function merge(target: any, source: any): any {
  for (const key in source) {
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
      // Should skip these!
    }
    target[key] = source[key];  // Prototype pollution
  }
  return target;
}

// Express app with vulnerable configuration
const app = express();

// HIGH: CORS allow all
app.use((req: Request, res: Response, next: NextFunction) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Credentials', 'true');
  next();
});

// HIGH: Verbose error handling
app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
  res.status(500).json({
    error: err.message,
    stack: err.stack,  // CRITICAL: Stack trace exposed
  });
});

// CRITICAL: NoSQL injection
async function findUser(username: string, password: string): Promise<any> {
  // MongoDB injection if username/password are objects
  // return User.findOne({ username: username, password: password });
}

// HIGH: Regex DoS (ReDoS)
function validateEmail(email: string): boolean {
  const regex = /^([a-zA-Z0-9_\.\-])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,4})+$/;
  return regex.test(email);  // Potential ReDoS
}

export { CONFIG, dbConfig, pingHost, getUser, readFile, calculate };
