CREATE TABLE broad_code_user (
    id              INT PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    name            VARCHAR(25) NOT NULL UNIQUE,
    password        VARCHAR(40) NOT NULL
);