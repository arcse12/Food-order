import clientPromise from "@/libs/mongoConnect";
import {UserInfo} from "@/models/UserInfo";
import bcrypt from "bcrypt";
import * as mongoose from "mongoose";
import {User} from '@/models/User';
import NextAuth, {getServerSession} from "next-auth";
import CredentialsProvider from "next-auth/providers/credentials";
import GoogleProvider from "next-auth/providers/google";
import { MongoDBAdapter } from "@auth/mongodb-adapter"

export const authOptions = {
  secret: process.env.SECRET,
  adapter: MongoDBAdapter(clientPromise),
  providers: [
    GoogleProvider({
      clientId: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    }),
    CredentialsProvider({
      name: 'Credentials',
      id: 'credentials',
      credentials: {
        username: { label: "Email", type: "email", placeholder: "test@example.com" },
        password: { label: "Password", type: "password" },
      },
      async authorize(credentials, req) {
        const email = credentials?.email;
        const password = credentials?.password;

        if (!email || !password) {
          console.error("Missing email or password");
          throw new Error("Missing email or password");
        }

        try {
          await mongoose.connect(process.env.MONGO_URL);
          const user = await User.findOne({email});
          
          if (!user) {
            console.error(`No user found for email: ${email}`);
            return null;
          }
          
          const passwordOk = await bcrypt.compare(password, user.password);

          if (passwordOk) {
            return user;
          } else {
            console.error(`Invalid password for email: ${email}`);
            return null;
          }
        } catch (error) {
          console.error("Error in authorize function:", error);
          throw new Error("An error occurred during authentication");
        }
      }
    })
  ],
  callbacks: {
    async signIn({ user, account, profile, email, credentials }) {
      console.log("SignIn callback:", { user, account, profile, email });
      return true;
    },
    async jwt({ token, user, account, profile, isNewUser }) {
      console.log("JWT callback:", { token, user, account, profile, isNewUser });
      return token;
    },
    async session({ session, user, token }) {
      console.log("Session callback:", { session, user, token });
      return session;
    }
  },
  pages: {
    signIn: '/auth/signin',
    error: '/auth/error',
  },
  debug: process.env.NODE_ENV === 'development',
};

export async function isAdmin() {
  const session = await getServerSession(authOptions);
  const userEmail = session?.user?.email;
  if (!userEmail) {
    return false;
  }
  const userInfo = await UserInfo.findOne({email:userEmail});
  if (!userInfo) {
    return false;
  }
  return userInfo.admin;
}

const handler = NextAuth(authOptions);

export { handler as GET, handler as POST }