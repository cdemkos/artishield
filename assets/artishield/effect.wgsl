// Fullscreen effect: simple brightening + mild vignette.
// Vertex shader produces full-screen triangle/quad; fragment samples input texture.

@group(0) @binding(0) var samp : sampler;
@group(0) @binding(1) var tex  : texture_2d<f32>;

struct VertexOutput {
    @builtin(position) pos: vec4<f32>;
    @location(0) uv: vec2<f32>;
};

@vertex
fn vs_main(@builtin(vertex_index) v_idx: u32) -> VertexOutput {
    var verts = array<vec2<f32>, 6>(
        vec2<f32>(-1.0, -1.0), vec2<f32>(1.0, -1.0), vec2<f32>(-1.0, 1.0),
        vec2<f32>(-1.0, 1.0),  vec2<f32>(1.0, -1.0), vec2<f32>(1.0, 1.0)
    );
    var uvs = array<vec2<f32>, 6>(
        vec2<f32>(0.0, 1.0), vec2<f32>(1.0, 1.0), vec2<f32>(0.0, 0.0),
        vec2<f32>(0.0, 0.0), vec2<f32>(1.0, 1.0), vec2<f32>(1.0, 0.0)
    );
    var out: VertexOutput;
    out.pos = vec4<f32>(verts[v_idx], 0.0, 1.0);
    out.uv = uvs[v_idx];
    return out;
}

@fragment
fn fs_main(in: VertexOutput) -> @location(0) vec4<f32> {
    let c = textureSample(tex, samp, in.uv);
    // brighten
    let col = c.rgb * 1.05;
    // vignette
    let uv = in.uv * 2.0 - vec2<f32>(1.0,1.0);
    let dist = length(uv);
    let vignette = smoothstep(0.8, 1.0, dist);
    let final_col = col * (1.0 - 0.5 * vignette);
    return vec4<f32>(final_col, c.a);
}

