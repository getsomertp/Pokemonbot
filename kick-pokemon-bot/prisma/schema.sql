generator client {
  provider = "prisma-client-js"
}

datasource db {
  provider = "postgresql"
  url      = env("DATABASE_URL")
}

model User {
  id          String         @id @default(uuid())
  createdAt   DateTime       @default(now())
  displayName String?
  identities  UserIdentity[]
  catches     Catch[]
}

model UserIdentity {
  id             String   @id @default(uuid())
  userId         String
  platform       String   // "kick" now, "discord" later
  platformUserId String?  // kick user id if you store it later
  handle         String   // username
  createdAt      DateTime @default(now())

  user User @relation(fields: [userId], references: [id])

  @@unique([platform, handle])
}

model Spawn {
  id        String   @id @default(uuid())
  pokemon   String
  tier      String   // common/uncommon/rare/epic/legendary
  isShiny   Boolean  @default(false)
  spawnedAt DateTime @default(now())
  expiresAt DateTime
  caughtAt  DateTime?
  caughtBy  String?
  caughtByUser User? @relation(fields: [caughtBy], references: [id])

  catches Catch[]
}

model Catch {
  id           String   @id @default(uuid())
  userId       String
  spawnId      String
  pokemon      String
  tier         String
  isShiny      Boolean  @default(false)
  pointsEarned Int
  caughtAt     DateTime @default(now())
  speedMs      Int

  user  User  @relation(fields: [userId], references: [id])
  spawn Spawn @relation(fields: [spawnId], references: [id])

  @@index([caughtAt])
  @@index([userId, caughtAt])
}

model Setting {
  key   String @id
  value String
  updatedAt DateTime @updatedAt
}
