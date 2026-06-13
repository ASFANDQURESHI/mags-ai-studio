import { Controller, Get, Patch, Body, UseGuards } from '@nestjs/common';
import { UsersService } from './users.service';
import { UpdateProfileDto } from './dto/update-profile.dto';
import { JwtGuard } from '@/auth/guards/jwt.guard';
import { CurrentUser } from '@/auth/decorators/current-user.decorator';

@Controller('users')
export class UsersController {
  constructor(private usersService: UsersService) {}

  /**
   * Get current user profile
   */
  @Get('me')
  @UseGuards(JwtGuard)
  async getProfile(@CurrentUser() user: any) {
    return await this.usersService.getUserProfile(user.sub);
  }

  /**
   * Update user profile
   */
  @Patch('me')
  @UseGuards(JwtGuard)
  async updateProfile(
    @CurrentUser() user: any,
    @Body() updateProfileDto: UpdateProfileDto,
  ) {
    return await this.usersService.updateUserProfile(user.sub, updateProfileDto);
  }
}
