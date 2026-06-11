import 'dotenv/config';
import { Sequelize, DataTypes } from 'sequelize';

const databaseUrl = process.env.DATABASE_URL || (
  process.env.PG_HOST && process.env.PG_DATABASE && process.env.PG_USER && process.env.PG_PASSWORD
    ? `postgres://${encodeURIComponent(process.env.PG_USER)}:${encodeURIComponent(process.env.PG_PASSWORD)}@${process.env.PG_HOST}:${process.env.PG_PORT || 5432}/${process.env.PG_DATABASE}`
    : null
);

export const dbEnabled = Boolean(databaseUrl);
export let dbAvailable = dbEnabled;
let fallbackLogged = false;

export function markDatabaseUnavailable(error) {
  dbAvailable = false;
  if (!fallbackLogged) {
    console.warn('PostgreSQL unavailable. Falling back to JSON storage.');
    fallbackLogged = true;
  }
  if (error) {
    console.warn(`PostgreSQL connection detail: ${error.message}`);
  }
}

export const sequelize = dbEnabled
  ? new Sequelize(databaseUrl, {
      dialect: 'postgres',
      logging: false,
      dialectOptions: process.env.PG_SSL === 'true' ? { ssl: { require: true, rejectUnauthorized: false } } : {},
      define: {
        timestamps: true,
        underscored: false
      }
    })
  : null;

export const User = dbEnabled
  ? sequelize.define('User', {
      id: {
        type: DataTypes.UUID,
        defaultValue: DataTypes.UUIDV4,
        primaryKey: true
      },
      name: {
        type: DataTypes.STRING,
        allowNull: false,
        validate: {
          len: [2, 255]
        }
      },
      email: {
        type: DataTypes.STRING,
        allowNull: false,
        unique: true,
        validate: {
          isEmail: true
        }
      },
      password: {
        type: DataTypes.TEXT,
        allowNull: false
      },
      role: {
        type: DataTypes.STRING,
        allowNull: false,
        defaultValue: 'user'
      },
      isActive: {
        type: DataTypes.BOOLEAN,
        allowNull: false,
        defaultValue: true
      }
    }, {
      tableName: 'users'
    })
  : null;

export const Contact = dbEnabled
  ? sequelize.define('Contact', {
      id: {
        type: DataTypes.UUID,
        defaultValue: DataTypes.UUIDV4,
        primaryKey: true
      },
      name: {
        type: DataTypes.STRING,
        allowNull: false
      },
      email: {
        type: DataTypes.STRING,
        allowNull: false,
        validate: {
          isEmail: true
        }
      },
      phone: {
        type: DataTypes.STRING,
        allowNull: true
      },
      service: {
        type: DataTypes.STRING,
        allowNull: false
      },
      message: {
        type: DataTypes.TEXT,
        allowNull: false
      },
      status: {
        type: DataTypes.STRING,
        allowNull: false,
        defaultValue: 'new'
      }
    }, {
      tableName: 'contacts'
    })
  : null;

export async function syncDatabase() {
  if (!dbEnabled) {
    markDatabaseUnavailable();
    return false;
  }

  try {
    await sequelize.authenticate();
    await sequelize.sync({ alter: true });
    console.log('✅ PostgreSQL database connected and synchronized.');
    return true;
  } catch (error) {
    markDatabaseUnavailable(error);
    return false;
  }
}
