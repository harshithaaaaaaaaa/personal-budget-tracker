CREATE TABLE users(
id SERIAL PRIMARY KEY,
email VARCHAR(100) NOT NULL UNIQUE,
password VARCHAR(100)
);

CREATE TABLE INCOME (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    source VARCHAR(100),
    amount INT,
    income_date DATE,
    month VARCHAR(20),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE EXPENSE (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    category VARCHAR(100),
    amount INT,
    expense_date DATE,
    month VARCHAR(20),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE BUDGET (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    budget_month DATE NOT NULL,
    budget_amount NUMERIC(10, 2) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE MONTHLY_BALANCE (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    balance NUMERIC(10, 2) NOT NULL,
    balance_month DATE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
