//! Bevy render-graph node for the ArtiShield fullscreen post-processing pass.
//!
//! The pass samples the main view texture and applies a subtle brightness +
//! vignette effect (WGSL shader in `assets/artishield/effect.wgsl`).
//!
//! Both LDR (`TextureFormat::bevy_default()`) and HDR (`Rgba16Float`) cameras
//! are supported — the correct pipeline variant is selected per view.

use bevy::prelude::*;
use bevy::reflect::TypeUuid;
use bevy::render::extract_resource::ExtractResource;
use bevy::render::render_graph::{Node, NodeRunError, RenderGraph, RenderGraphContext};
use bevy::render::render_resource::{
    AddressMode, BindGroupDescriptor, BindGroupEntry, BindGroupLayout, BindGroupLayoutDescriptor,
    BindGroupLayoutEntry, BindingResource, BindingType, BlendState, CachedPipelineState,
    CachedRenderPipelineId, ColorTargetState, ColorWrites, FilterMode, FragmentState, LoadOp,
    MultisampleState, Operations, PipelineCache, PrimitiveState, RenderPassColorAttachment,
    RenderPassDescriptor, RenderPipelineDescriptor, Sampler, SamplerBindingType, SamplerDescriptor,
    Shader, ShaderStages, TextureFormat, TextureSampleType, TextureViewDimension, VertexState,
};
use bevy::render::renderer::{RenderContext, RenderDevice};
use bevy::render::texture::BevyDefault as _;
use bevy::render::view::{ExtractedView, ViewTarget};
use std::sync::atomic::{AtomicBool, Ordering};

const NODE_NAME: &str = "artishield_pass";

/// Stable handle for the embedded WGSL effect shader.
pub const ARTISHIELD_SHADER_HANDLE: HandleUntyped =
    HandleUntyped::weak_from_u64(Shader::TYPE_UUID, 0x4172_7469_5368_6965_u64);

// ── Settings ──────────────────────────────────────────────────────────────────

/// Settings for the ArtiShield post-processing pass.
///
/// Automatically mirrored to the render world each frame via [`ExtractResource`].
#[derive(Resource, Clone, Default, ExtractResource)]
pub struct ArtishieldSettings {
    /// Enable or disable the fullscreen post-processing overlay.
    pub enabled: bool,
    /// Intensity of the visual effect (0.0 = off, 1.0 = full).
    pub intensity: f32,
}

// ── Pipeline resource ─────────────────────────────────────────────────────────

/// GPU resources for the ArtiShield render pass.
///
/// Two pipeline variants are kept: one for LDR (swapchain format) cameras and
/// one for HDR (`Rgba16Float`) cameras.  The correct variant is chosen per view
/// in [`ArtishieldPassNode::run`].
#[derive(Resource)]
pub struct ArtishieldPipeline {
    /// LDR pipeline (`TextureFormat::bevy_default()`).
    pub pipeline_id: CachedRenderPipelineId,
    /// HDR pipeline (`TextureFormat::Rgba16Float`).
    pub hdr_pipeline_id: CachedRenderPipelineId,
    /// Shared bind-group layout (sampler + texture view).
    pub bind_group_layout: BindGroupLayout,
    /// Linear sampler used by both pipeline variants.
    pub sampler: Sampler,
}

impl ArtishieldPipeline {
    /// Select the pipeline ID appropriate for this view's HDR setting.
    #[inline]
    pub fn pipeline_for(&self, hdr: bool) -> CachedRenderPipelineId {
        if hdr {
            self.hdr_pipeline_id
        } else {
            self.pipeline_id
        }
    }
}

impl FromWorld for ArtishieldPipeline {
    fn from_world(world: &mut World) -> Self {
        let (sampler, bind_group_layout) = {
            let render_device = world.resource::<RenderDevice>();

            let sampler = render_device.create_sampler(&SamplerDescriptor {
                label: Some("artishield_sampler"),
                address_mode_u: AddressMode::ClampToEdge,
                address_mode_v: AddressMode::ClampToEdge,
                address_mode_w: AddressMode::ClampToEdge,
                mag_filter: FilterMode::Linear,
                min_filter: FilterMode::Linear,
                mipmap_filter: FilterMode::Nearest,
                ..Default::default()
            });

            let bind_group_layout =
                render_device.create_bind_group_layout(&BindGroupLayoutDescriptor {
                    label: Some("artishield_bgl"),
                    entries: &[
                        BindGroupLayoutEntry {
                            binding: 0,
                            visibility: ShaderStages::FRAGMENT,
                            ty: BindingType::Sampler(SamplerBindingType::Filtering),
                            count: None,
                        },
                        BindGroupLayoutEntry {
                            binding: 1,
                            visibility: ShaderStages::FRAGMENT,
                            ty: BindingType::Texture {
                                multisampled: false,
                                view_dimension: TextureViewDimension::D2,
                                sample_type: TextureSampleType::Float { filterable: true },
                            },
                            count: None,
                        },
                    ],
                });

            (sampler, bind_group_layout)
        };

        let shader = ARTISHIELD_SHADER_HANDLE.typed::<Shader>();
        let (pipeline_id, hdr_pipeline_id) = {
            let pipeline_cache = world.resource::<PipelineCache>();

            let ldr = pipeline_cache.queue_render_pipeline(pipeline_desc(
                shader.clone(),
                bind_group_layout.clone(),
                TextureFormat::bevy_default(),
                "artishield_pipeline_ldr",
            ));
            let hdr = pipeline_cache.queue_render_pipeline(pipeline_desc(
                shader,
                bind_group_layout.clone(),
                TextureFormat::Rgba16Float,
                "artishield_pipeline_hdr",
            ));
            (ldr, hdr)
        };

        ArtishieldPipeline {
            pipeline_id,
            hdr_pipeline_id,
            bind_group_layout,
            sampler,
        }
    }
}

/// Build a [`RenderPipelineDescriptor`] for the given target format.
fn pipeline_desc(
    shader: Handle<Shader>,
    bind_group_layout: BindGroupLayout,
    format: TextureFormat,
    label: &'static str,
) -> RenderPipelineDescriptor {
    RenderPipelineDescriptor {
        label: Some(label.into()),
        layout: vec![bind_group_layout],
        vertex: VertexState {
            shader: shader.clone(),
            entry_point: "vs_main".into(),
            shader_defs: vec![],
            buffers: vec![],
        },
        fragment: Some(FragmentState {
            shader,
            entry_point: "fs_main".into(),
            shader_defs: vec![],
            targets: vec![Some(ColorTargetState {
                format,
                blend: Some(BlendState::ALPHA_BLENDING),
                write_mask: ColorWrites::ALL,
            })],
        }),
        primitive: PrimitiveState::default(),
        depth_stencil: None,
        multisample: MultisampleState::default(),
        push_constant_ranges: vec![],
    }
}

// ── Pass node ─────────────────────────────────────────────────────────────────

/// Records the fullscreen render pass for the ArtiShield effect.
///
/// Iterates over all views itself (no `view_entity` input slot) to avoid the
/// crash that occurred when the node was placed in the main render graph where
/// the slot is never connected.
///
/// Uses `ViewTarget::post_process_write()` so that source and destination are
/// always different textures — reading and writing the same texture in one pass
/// is a GPU validation error.
pub struct ArtishieldPassNode {
    query: QueryState<(Entity, &'static ViewTarget, Option<&'static ExtractedView>)>,
}

impl FromWorld for ArtishieldPassNode {
    fn from_world(world: &mut World) -> Self {
        Self {
            query: world.query(),
        }
    }
}

impl Node for ArtishieldPassNode {
    // No input slots — we iterate views ourselves in `run`.
    fn update(&mut self, world: &mut World) {
        self.query.update_archetypes(world);
    }

    fn run(
        &self,
        _graph: &mut RenderGraphContext<'_>,
        render_context: &mut RenderContext,
        world: &World,
    ) -> Result<(), NodeRunError> {
        let settings = world.resource::<ArtishieldSettings>();
        if !settings.enabled {
            return Ok(());
        }

        let pipeline_res = world.resource::<ArtishieldPipeline>();
        let pipeline_cache = world.resource::<PipelineCache>();
        let render_device = world.resource::<RenderDevice>();

        for (entity, view_target, maybe_view) in self.query.iter_manual(world) {
            let hdr = maybe_view.map_or(false, |v| v.hdr);
            let pipeline_id = pipeline_res.pipeline_for(hdr);

            // Skip this view until the pipeline has finished compiling.
            if !matches!(
                pipeline_cache.get_render_pipeline_state(pipeline_id),
                CachedPipelineState::Ok(_)
            ) {
                continue;
            }
            let Some(pipeline) = pipeline_cache.get_render_pipeline(pipeline_id) else {
                continue;
            };

            // post_process_write() swaps the ping-pong buffers atomically and
            // returns separate source (to sample) and destination (to draw to).
            // This avoids the GPU validation error of sampling and writing the
            // same texture in one render pass.
            let post_process = view_target.post_process_write();

            let bind_group = render_device.create_bind_group(&BindGroupDescriptor {
                label: Some("artishield_bind_group"),
                layout: &pipeline_res.bind_group_layout,
                entries: &[
                    BindGroupEntry {
                        binding: 0,
                        resource: BindingResource::Sampler(&pipeline_res.sampler),
                    },
                    BindGroupEntry {
                        binding: 1,
                        resource: BindingResource::TextureView(post_process.source),
                    },
                ],
            });

            let color_attachment = RenderPassColorAttachment {
                view: post_process.destination,
                resolve_target: None,
                ops: Operations {
                    load: LoadOp::Load,
                    store: true,
                },
            };

            let mut render_pass =
                render_context
                    .command_encoder()
                    .begin_render_pass(&RenderPassDescriptor {
                        label: Some("artishield_fullscreen_pass"),
                        color_attachments: &[Some(color_attachment)],
                        depth_stencil_attachment: None,
                    });

            render_pass.set_pipeline(pipeline);
            render_pass.set_bind_group(0, &bind_group, &[]);
            // 6 vertices → full-screen quad; no vertex buffer needed.
            render_pass.draw(0..6, 0..1);

            // Suppress unused-variable warning when there is only one view.
            let _ = entity;
        }

        Ok(())
    }
}

// ── Graph registration ────────────────────────────────────────────────────────

/// Register the ArtiShield pass node into the render graph of `render_world`.
///
/// The node is placed after `CAMERA_DRIVER` so it runs once all per-view
/// camera sub-graphs have finished rendering.
///
/// Safe to call multiple times — subsequent calls are no-ops.
pub fn register_node(render_world: &mut World) {
    static NODE_REGISTERED: AtomicBool = AtomicBool::new(false);
    if NODE_REGISTERED.swap(true, Ordering::SeqCst) {
        return;
    }

    let node = ArtishieldPassNode::from_world(render_world);
    let mut graph = render_world.resource_mut::<RenderGraph>();
    graph.add_node(NODE_NAME, node);
    graph.add_node_edge(bevy::render::main_graph::node::CAMERA_DRIVER, NODE_NAME);
    info!("Registered artishield_pass node into render graph");
}
