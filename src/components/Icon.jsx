import React from 'react';
import {
  ArrowRight, BellRing, Check, Home, Layers, MenuFold, MenuUnfold,
  NetworkTree, Search, Shield, Star, Attention, HamburgerButton, Close,
  User, Lock, PreviewOpen, PreviewClose, Refresh,
} from '@icon-park/react';

const icons = {
  arrow: ArrowRight,
  bell: BellRing,
  check: Check,
  home: Home,
  layers: Layers,
  menu: HamburgerButton,
  network: NetworkTree,
  audit: Layers,
  database: Layers,
  refresh: Refresh,
  checkCircle: Check,
  search: Search,
  shield: Shield,
  star: Star,
  alert: Attention,
  flow: NetworkTree,
  close: Close,
  user: User,
  lock: Lock,
  show: PreviewOpen,
  hide: PreviewClose,
  collapse: MenuFold,
  expand: MenuUnfold,
};

export default function Icon({ name, size = 20, solid = false }) {
  const Component = icons[name];
  return Component ? <Component theme={solid ? 'filled' : 'outline'} size={size} strokeWidth={3} fill="currentColor" aria-hidden="true" /> : null;
}
