export class AuthResponseDto {
  accessToken: string;
  refreshToken: string;
  user: {
    id: string;
    email: string;
    username: string;
    firstName: string | null;
    lastName: string | null;
    avatar: string | null;
    roles: string[];
    permissions: string[];
    emailVerified: boolean;
    isActive: boolean;
    lastLoginAt: Date | null;
    createdAt: Date;
  };
}
