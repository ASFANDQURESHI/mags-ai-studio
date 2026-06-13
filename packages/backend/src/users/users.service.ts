import { Injectable, NotFoundException, BadRequestException } from '@nestjs/common';
import { PrismaService } from '@/prisma/prisma.service';
import { UpdateProfileDto } from './dto/update-profile.dto';
import * as bcrypt from 'bcrypt';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class UsersService {
  constructor(
    private prisma: PrismaService,
    private configService: ConfigService,
  ) {}

  /**
   * Get user profile
   */
  async getUserProfile(userId: string) {
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
      throw new NotFoundException('User not found');
    }

    return this.buildUserResponse(user);
  }

  /**
   * Update user profile
   */
  async updateUserProfile(userId: string, updateProfileDto: UpdateProfileDto) {
    const { firstName, lastName, avatar, bio, phone, password } = updateProfileDto;

    const updateData: any = {
      firstName,
      lastName,
      avatar,
      bio,
      phone,
    };

    // If password is provided, hash it
    if (password) {
      this.validatePasswordStrength(password);
      updateData.password = await bcrypt.hash(
        password,
        this.configService.get('security.bcryptRounds'),
      );
    }

    const user = await this.prisma.user.update({
      where: { id: userId },
      data: updateData,
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

    return this.buildUserResponse(user);
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

    if (!/[A-Z]/.test(password)) {
      throw new BadRequestException('Password must contain at least one uppercase letter');
    }

    if (!/[a-z]/.test(password)) {
      throw new BadRequestException('Password must contain at least one lowercase letter');
    }

    if (!/[0-9]/.test(password)) {
      throw new BadRequestException('Password must contain at least one number');
    }

    if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
      throw new BadRequestException('Password must contain at least one special character');
    }
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
      bio: user.bio,
      phone: user.phone,
      roles,
      permissions,
      emailVerified: user.emailVerified,
      isActive: user.isActive,
      lastLoginAt: user.lastLoginAt,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
    };
  }
}
