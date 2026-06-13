import { Injectable, UnauthorizedException } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { Inject } from '@nestjs/common';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { Cache } from 'cache-manager';

@Injectable()
export class JwtGuard extends AuthGuard('jwt') {
  constructor(@Inject(CACHE_MANAGER) private cacheManager: Cache) {
    super();
  }

  async canActivate(context: any): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const token = request.headers.authorization?.split(' ')[1];

    if (!token) {
      throw new UnauthorizedException('Missing authorization token');
    }

    // Check if token is blacklisted
    const isBlacklisted = await this.cacheManager.get(`blacklist:${token}`);
    if (isBlacklisted) {
      throw new UnauthorizedException('Token has been revoked');
    }

    return (await super.canActivate(context)) as boolean;
  }
}
