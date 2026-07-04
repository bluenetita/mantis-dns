type BrandMarkProps = {
  size?: number;
};

export function BrandMark({ size = 22 }: BrandMarkProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 100 100" aria-hidden="true">
      <g transform="translate(0,5)">
        <g fill="none" stroke="#4c6ef5" strokeWidth={2.4} strokeLinecap="round" strokeLinejoin="round">
          <polyline points="28,24 18,10 8,-2" />
          <polyline points="72,24 82,10 92,-2" />
        </g>
        <g stroke="#fff" strokeWidth={0.6} strokeLinejoin="round">
          <polygon points="8,40 28,24 50,46" fill="#748ffc" />
          <polygon points="8,40 50,46 26,56" fill="#4c6ef5" />
          <polygon points="92,40 72,24 50,46" fill="#748ffc" />
          <polygon points="92,40 50,46 74,56" fill="#4c6ef5" />
          <polygon points="26,56 50,46 50,92" fill="#4c6ef5" />
          <polygon points="74,56 50,46 50,92" fill="#3b5bdb" />
        </g>
      </g>
    </svg>
  );
}
