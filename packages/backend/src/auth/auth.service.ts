import {
  Injectable,
  UnauthorizedException,
  BadRequestException,
  ConflictException,
  Inject,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { PrismaService } from '@/prisma/prisma.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { AuthResponseDto } from './dto/auth-response.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { Cache } from 'cache-manager';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
    private configService: ConfigService,
    @Inject(CACHE_MANAGER) private cacheManager: Cache,
  ) {}

  /**
   * Register a new user
   */
  async register(registerDto: RegisterDto, ipAddress: string): Promise<AuthResponseDto> {
    const { email, username, password, confirmPassword, firstName, lastName } = registerDto;

    // Validate passwords match
    if (password !== confirmPassword) {
      throw new BadRequestException('Passwords do not match');
    }

    // Validate password strength
    this.validatePasswordStrength(password);

    // Check if user exists
    const existingUser = await this.prisma.user.findFirst({
      where: {
        OR: [{ email }, { username }],
      },
    });

    if (existingUser) {
      throw new ConflictException('Email or username already exists');
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(
      password,
      this.configService.get('security.bcryptRounds'),
    );

    // Create user
    const user = await this.prisma.user.create({
      data: {
        email,
        username,
        password: hashedPassword,
        firstName,
        lastName,
      },
      include: {
        userRoles: {
          include: {
            role: {
              include: {
                permissions: {
                  include: {
                    permission: true,
                  },
                },
              },
            },
          },
        },
      },
    });

    // Assign MEMBER role by default
    const memberRole = await this.prisma.role.findUnique({
      where: { name: 'MEMBER' },
    });

    if (memberRole) {
      await this.prisma.userRole.create({
        data: {
          userId: user.id,
          roleId: memberRole.id,
        },
      });
    }

    // Generate tokens
    const { accessToken, refreshToken } = await this.generateTokens(user.id);

    // Create session
    await this.prisma.session.create({
      data: {
        userId: user.id,
        token: accessToken,
        ipAddress,
        expiresAt: new Date(Date.now() + 15 * 60 * 1000), // 15 minutes
      },
    });

    return this.buildAuthResponse(user, accessToken, refreshToken);
  }

  /**
   * Login user
   */
  async login(loginDto: LoginDto, ipAddress: string): Promise<AuthResponseDto> {
    const { email, password } = loginDto;

    // Check rate limiting
    const lockoutKey = `lockout:${email}`;
    const lockoutCount = await this.cacheManager.get<number>(lockoutKey);

    if (lockoutCount && lockoutCount >= this.configService.get('security.maxLoginAttempts')) {
      throw new UnauthorizedException('Account temporarily locked. Try again later.');
    }

    // Find user
    const user = await this.prisma.user.findUnique({
      where: { email },
      include: {
        userRoles: {
          include: {
            role: {
              include: {
                permissions: {
                  include: {
                    permission: true,
                  },
                },
              },
            },
          },
        },
      },
    });

    if (!user) {
      // Increment lockout counter
      await this.cacheManager.set(
        lockoutKey,
        (lockoutCount || 0) + 1,
        this.configService.get('security.lockoutDuration') * 1000,
      );
      throw new UnauthorizedException('Invalid email or password');
    }

    // Verify password
    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      // Increment lockout counter
      await this.cacheManager.set(
        lockoutKey,
        (lockoutCount || 0) + 1,
        this.configService.get('security.lockoutDuration') * 1000,
      );
      throw new UnauthorizedException('Invalid email or password');
    }

    // Check if user is active
    if (!user.isActive) {
      throw new UnauthorizedException('User account is inactive');
    }

    // Clear lockout counter
    await this.cacheManager.del(lockoutKey);

    // Update last login
    await this.prisma.user.update({
      where: { id: user.id },
      data: { lastLoginAt: new Date() },
    });

    // Generate tokens
    const { accessToken, refreshToken } = await this.generateTokens(user.id);

    // Create session
    await this.prisma.session.create({
      data: {
        userId: user.id,
        token: accessToken,
        ipAddress,
        expiresAt: new Date(Date.now() + 15 * 60 * 1000), // 15 minutes
      },
    });

    return this.buildAuthResponse(user, accessToken, refreshToken);
  }

  /**
   * Logout user
   */
  async logout(userId: string, token: string): Promise<void> {
    // Revoke session
    await this.prisma.session.update({
      where: { token },
      data: { isRevoked: true },
    });

    // Blacklist token in Redis
    const payload = this.jwtService.decode(token);
    const expiresIn = (payload.exp - Math.floor(Date.now() / 1000)) * 1000;

    if (expiresIn > 0) {
      await this.cacheManager.set(`blacklist:${token}`, true, expiresIn);
    }
  }

  /**
   * Refresh access token
   */
  async refreshTokens(refreshToken: string): Promise<AuthResponseDto> {
    try {
      // Verify refresh token
      const payload = this.jwtService.verify(refreshToken, {
        secret: this.configService.get('jwt.secret'),
      });

      // Check if refresh token exists and not revoked
      const storedRefreshToken = await this.prisma.refreshToken.findUnique({
        where: { token: refreshToken },
      });

      if (!storedRefreshToken || storedRefreshToken.isRevoked) {
        throw new UnauthorizedException('Invalid refresh token');
      }

      // Check if token is expired
      if (new Date() > storedRefreshToken.expiresAt) {
        throw new UnauthorizedException('Refresh token expired');
      }

      // Get user with roles and permissions
      const user = await this.prisma.user.findUnique({
        where: { id: payload.sub },
        include: {
          userRoles: {
            include: {
              role: {
                include: {
                  permissions: {
                    include: {
                      permission: true,
                    },
                  },
                },
              },
            },
          },
        },
      });

      if (!user || !user.isActive) {
        throw new UnauthorizedException('User not found or inactive');
      }

      // Generate new tokens
      const { accessToken, refreshToken: newRefreshToken } = await this.generateTokens(user.id);

      // Revoke old refresh token
      await this.prisma.refreshToken.update({
        where: { id: storedRefreshToken.id },
        data: { isRevoked: true, rotatedAt: new Date() },
      });

      return this.buildAuthResponse(user, accessToken, newRefreshToken);
    } catch (error) {
      throw new UnauthorizedException('Invalid refresh token');
    }
  }

  /**
   * Get current user
   */
  async getCurrentUser(userId: string) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      include: {
        userRoles: {
          include: {
            role: {
              include: {
                permissions: {
                  include: {
                    permission: true,
                  },
                },
              },
            },
          },
        },
      },
    });

    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    return this.buildUserResponse(user);
  }

  /**
   * Validate user by ID
   */
  async validateUser(userId: string) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      include: {
        userRoles: {
          include: {
            role: {
              include: {
                permissions: {
                  include: {
                    permission: true,
                  },
                },
              },
            },
          },
        },
      },
    });

    if (!user) {
      return null;
    }

    return this.buildUserResponse(user);
  }

  /**
   * Request password reset
   */
  async requestPasswordReset(forgotPasswordDto: ForgotPasswordDto): Promise<{ message: string }> {
    const { email } = forgotPasswordDto;

    const user = await this.prisma.user.findUnique({
      where: { email },
    });

    // Don't reveal if user exists
    if (!user) {
      return { message: 'If an account exists, a reset link has been sent.' };
    }

    // Create password reset token
    const resetToken = this.jwtService.sign(
      { sub: user.id, type: 'password-reset' },
      { expiresIn: '1h', secret: this.configService.get('jwt.secret') },
    );

    // Store reset token
    await this.prisma.passwordReset.create({
      data: {
        userId: user.id,
        token: resetToken,
        expiresAt: new Date(Date.now() + 60 * 60 * 1000), // 1 hour
      },
    });

    // TODO: Send email with reset link
    console.log(`Password reset link: ${process.env.FRONTEND_URL}/reset-password?token=${resetToken}`);

    return { message: 'If an account exists, a reset link has been sent.' };
  }

  /**
   * Generate JWT tokens
   */
  private async generateTokens(userId: string) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      include: {
        userRoles: {
          include: {
            role: {
              include: {
                permissions: {
                  include: {
                    permission: true,
                  },
                },
              },
            },
          },
        },
      },
    });

    const permissions = user.userRoles
      .flatMap((ur) => ur.role.permissions)
      .map((rp) => rp.permission.name);

    const roles = user.userRoles.map((ur) => ur.role.name);

    // Access token (15 minutes)
    const accessToken = this.jwtService.sign(
      {
        sub: user.id,
        email: user.email,
        username: user.username,
        roles,
        permissions,
      },
      {
        expiresIn: this.configService.get('jwt.expirationTime'),
        issuer: this.configService.get('jwt.issuer'),
        audience: this.configService.get('jwt.audience'),
      },
    );

    // Refresh token (7 days)
    const refreshTokenExpiry = new Date();
    refreshTokenExpiry.setDate(refreshTokenExpiry.getDate() + 7);

    const refreshToken = this.jwtService.sign(
      {
        sub: user.id,
        type: 'refresh',
      },
      {
        expiresIn: this.configService.get('jwt.refreshTokenExpiration'),
        issuer: this.configService.get('jwt.issuer'),
        audience: this.configService.get('jwt.audience'),
      },
    );

    // Store refresh token
    await this.prisma.refreshToken.create({
      data: {
        userId: user.id,
        token: refreshToken,
        expiresAt: refreshTokenExpiry,
      },
    });

    return { accessToken, refreshToken };
  }

  /**
   * Validate password strength
   */
  private validatePasswordStrength(password: string): void {
    const minLength = this.configService.get('security.passwordMinLength');

    if (password.length < minLength) {
      throw new BadRequestException(
        `Password must be at least ${minLength} characters long`,
      );
    }

    // Check for uppercase letter
    if (!/[A-Z]/.test(password)) {
      throw new BadRequestException('Password must contain at least one uppercase letter');
    }

    // Check for lowercase letter
    if (!/[a-z]/.test(password)) {
      throw new BadRequestException('Password must contain at least one lowercase letter');
    }

    // Check for number
    if (!/[0-9]/.test(password)) {
      throw new BadRequestException('Password must contain at least one number');
    }

    // Check for special character
    if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
      throw new BadRequestException('Password must contain at least one special character');
    }
  }

  /**
   * Build auth response
   */
  private buildAuthResponse(user: any, accessToken: string, refreshToken: string): AuthResponseDto {
    return {
      accessToken,
      refreshToken,
      user: this.buildUserResponse(user),
    };
  }

  /**
   * Build user response
   */
  private buildUserResponse(user: any) {
    const roles = user.userRoles.map((ur) => ur.role.name);
    const permissions = user.userRoles
      .flatMap((ur) => ur.role.permissions)
      .map((rp) => rp.permission.name);

    return {
      id: user.id,
      email: user.email,
      username: user.username,
      firstName: user.firstName,
      lastName: user.lastName,
      avatar: user.avatar,
      roles,
      permissions,
      emailVerified: user.emailVerified,
      isActive: user.isActive,
      lastLoginAt: user.lastLoginAt,
      createdAt: user.createdAt,
    };
  }
}
