//! Bevy render-graph node for the ArtiShield fullscreen post-processing pass.

use bevy::prelude::*;
use bevy::reflect::TypeUuid;
use bevy::render::render_graph::{
    Node, NodeRunError, RenderGraph, RenderGraphContext, SlotInfo, SlotType,
};
use bevy::render::render_resource::{
    AddressMode, BindGroupLayout, BindGroupLayoutDescriptor, BindGroupLayoutEntry, BindingType,
    BlendState, CachedRenderPipelineId, ColorTargetState, ColorWrites, FilterMode, FragmentState,
    LoadOp, MultisampleState, Operations, PipelineCache, PrimitiveState,
    RenderPassColorAttachment, RenderPassDescriptor, RenderPipelineDescriptor, Sampler,
    SamplerBindingType, SamplerDescriptor, Shader, ShaderStages, TextureFormat,
    TextureSampleType, TextureViewDimension, VertexAttribute, VertexBufferLayout, VertexFormat,
    VertexState, VertexStepMode,
};
use bevy::render::renderer::{RenderContext, RenderDevice};
use bevy::render::texture::BevyDefault as _;
use bevy::render::view::ViewTarget;
use std::sync::atomic::{AtomicBool, Ordering};

const NODE_NAME: &str = "artishield_pass";

/// Stable handle for the embedded WGSL effect shader.
///
/// The UUID is ArtiShield-specific and must not collide with other crates.
pub const ARTISHIELD_SHADER_HANDLE: HandleUntyped =
    HandleUntyped::weak_from_u64(Shader::TYPE_UUID, 0x4172_7469_5368_6965_u64);

/// GPU resources owned by the ArtiShield render pass.
#[derive(Resource)]
pub struct ArtishieldPipeline {
    /// ID of the queued render pipeline (may be INVALID until compiled).
    pub pipeline_id: CachedRenderPipelineId,
    /// Bind group layout for the effect sampler + texture.
    pub bind_group_layout: BindGroupLayout,
    /// Linear sampler used to sample the main view texture.
    pub sampler: Sampler,
}

impl FromWorld for ArtishieldPipeline {
    fn from_world(world: &mut World) -> Self {
        // Create sampler + BGL while holding the RenderDevice borrow.
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

        // Queue the render pipeline via PipelineCache (compilation is async).
        let shader = ARTISHIELD_SHADER_HANDLE.typed::<Shader>();
        let pipeline_id = {
            let mut pipeline_cache = world.resource_mut::<PipelineCache>();
            pipeline_cache.queue_render_pipeline(RenderPipelineDescriptor {
                label: Some("artishield_pipeline".into()),
                // Pass the bind group layout directly — Bevy 0.11 takes Vec<BindGroupLayout>.
                layout: vec![bind_group_layout.clone()],
                vertex: VertexState {
                    shader: shader.clone(),
                    entry_point: "vs_main".into(),
                    shader_defs: vec![],
                    buffers: vec![VertexBufferLayout {
                        array_stride: std::mem::size_of::<[f32; 4]>() as u64,
                        step_mode: VertexStepMode::Vertex,
                        attributes: vec![
                            VertexAttribute {
                                format: VertexFormat::Float32x2,
                                offset: 0,
                                shader_location: 0,
                            },
                            VertexAttribute {
                                format: VertexFormat::Float32x2,
                                offset: 8,
                                shader_location: 1,
                            },
                        ],
                    }],
                },
                fragment: Some(FragmentState {
                    shader,
                    entry_point: "fs_main".into(),
                    shader_defs: vec![],
                    targets: vec![Some(ColorTargetState {
                        format: TextureFormat::bevy_default(),
                        blend: Some(BlendState::ALPHA_BLENDING),
                        write_mask: ColorWrites::ALL,
                    })],
                }),
                primitive: PrimitiveState::default(),
                depth_stencil: None,
                multisample: MultisampleState::default(),
                push_constant_ranges: vec![],
            })
        };

        ArtishieldPipeline {
            pipeline_id,
            bind_group_layout,
            sampler,
        }
    }
}

/// Extraction stage: copy resources from the main world into the render world.
pub fn extract_resources() {
    // Nothing to extract yet — placeholder for future resource mirroring.
}

/// Queue stage: placeholder for per-view bind group creation.
pub fn queue_node(_pipeline: Res<ArtishieldPipeline>) {
    // Bind groups would be created here once the pipeline is ready.
}

/// The actual [`Node`] that records the fullscreen render pass.
#[derive(Default)]
pub struct ArtishieldPassNode;

impl Node for ArtishieldPassNode {
    fn input(&self) -> Vec<SlotInfo> {
        vec![SlotInfo::new("view_entity", SlotType::Entity)]
    }

    fn update(&mut self, _world: &mut World) {}

    fn run(
        &self,
        graph: &mut RenderGraphContext,
        render_context: &mut RenderContext,
        world: &World,
    ) -> Result<(), NodeRunError> {
        // Resolve the view entity from the input slot.
        let view_entity = graph.get_input_entity("view_entity")?;

        let view_target = match world.get::<ViewTarget>(view_entity) {
            Some(vt) => vt,
            None => return Ok(()),
        };

        // Begin a render pass over the main view texture.
        let color_attachment = RenderPassColorAttachment {
            view: view_target.main_texture_view(),
            resolve_target: None,
            ops: Operations {
                load: LoadOp::Load,
                store: true,
            },
        };

        let _render_pass =
            render_context
                .command_encoder()
                .begin_render_pass(&RenderPassDescriptor {
                    label: Some("artishield_fullscreen_pass"),
                    color_attachments: &[Some(color_attachment)],
                    depth_stencil_attachment: None,
                });

        // Pipeline draw calls would go here once bind groups are created.
        // For now the pass is a no-op overlay; drop ends the render pass.

        Ok(())
    }
}

/// Register the ArtiShield pass node into `graph`, after the main opaque pass.
///
/// Safe to call multiple times — subsequent calls are no-ops.
pub fn register_node(graph: &mut RenderGraph) {
    static NODE_REGISTERED: AtomicBool = AtomicBool::new(false);
    if NODE_REGISTERED.swap(true, Ordering::SeqCst) {
        return;
    }
    graph.add_node(NODE_NAME, ArtishieldPassNode::default());
    // Run after the camera driver node (Bevy 0.11 main graph entry point).
    graph.add_node_edge(bevy::render::main_graph::node::CAMERA_DRIVER, NODE_NAME);
    info!("Registered artishield_pass node into render graph");
}
